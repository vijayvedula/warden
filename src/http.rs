//! Minimal MCP Streamable-HTTP transport over `std::net` (no async deps).
//!
//! Implements the JSON-response mode of MCP's Streamable HTTP: the client POSTs
//! a JSON-RPC message; Warden routes it through the same gateway as the stdio
//! path and returns a single `application/json` response (202 for
//! notifications). Server-initiated SSE streaming (GET) is not implemented --
//! request/response covers the proxy's needs. Thread-per-connection, sharing
//! the `Arc<Gateway>`. Also serves `GET /healthz` and `GET /metrics` for ops.

use crate::gateway::Gateway;
use crate::jsonrpc::{Request, Response};
use crate::util::now_unix;
use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

static SESSION_SEQ: AtomicU64 = AtomicU64::new(0);
/// Set by the SIGTERM/SIGINT handler -- stops accepting new connections.
static SHUTDOWN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// In-flight connections, so shutdown can drain before exit.
static ACTIVE: AtomicUsize = AtomicUsize::new(0);

/// Request a graceful shutdown (called from the signal handler -- atomic only).
pub fn request_shutdown() {
    SHUTDOWN.store(true, Ordering::SeqCst);
}

/// Whether a shutdown has been requested (the stdio loop checks this too).
pub fn shutting_down() -> bool {
    SHUTDOWN.load(Ordering::SeqCst)
}

/// Serve until shutdown, then drain in-flight connections up to `drain_secs`.
pub fn serve(addr: &str, gateway: Arc<Gateway>, drain_secs: u64) -> Result<(), String> {
    let listener = TcpListener::bind(addr).map_err(|e| format!("bind {addr}: {e}"))?;
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("nonblocking: {e}"))?;
    eprintln!("warden: HTTP transport on http://{addr}  (POST /  / GET /healthz / /metrics)");
    while !shutting_down() {
        match listener.accept() {
            Ok((s, _)) => {
                ACTIVE.fetch_add(1, Ordering::SeqCst);
                let g = gateway.clone();
                thread::spawn(move || {
                    if let Err(e) = handle(s, g) {
                        eprintln!("warden http: {e}");
                    }
                    ACTIVE.fetch_sub(1, Ordering::SeqCst);
                });
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(50)),
            Err(e) => eprintln!("warden http: accept error: {e}"),
        }
    }
    // Drain: stop accepting, let in-flight finish, bounded by drain_secs.
    eprintln!("warden: shutdown -- draining in-flight requests (<={drain_secs}s)...");
    for _ in 0..(drain_secs * 20) {
        if ACTIVE.load(Ordering::SeqCst) == 0 {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    let stuck = ACTIVE.load(Ordering::SeqCst);
    if stuck > 0 {
        eprintln!("warden: drain timeout -- {stuck} request(s) still in flight");
    }
    Ok(())
}

fn handle(stream: TcpStream, gateway: Arc<Gateway>) -> std::io::Result<()> {
    let mut reader = BufReader::new(&stream);

    // Request line: METHOD PATH HTTP/1.1
    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 {
        return Ok(());
    }
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("/").to_string();

    // Headers until the blank line; capture Content-Length, DPoP, Host, Authorization.
    let mut content_length = 0usize;
    let mut dpop: Option<String> = None;
    let mut host = String::new();
    let mut authorization: Option<String> = None;
    loop {
        let mut h = String::new();
        if reader.read_line(&mut h)? == 0 {
            break;
        }
        if h == "\r\n" || h == "\n" {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            let key = k.trim();
            if key.eq_ignore_ascii_case("content-length") {
                content_length = v.trim().parse().unwrap_or(0);
            } else if key.eq_ignore_ascii_case("dpop") {
                dpop = Some(v.trim().to_string());
            } else if key.eq_ignore_ascii_case("host") {
                host = v.trim().to_string();
            } else if key.eq_ignore_ascii_case("authorization") {
                authorization = Some(v.trim().to_string());
            }
        }
    }

    let w = &stream;
    // Endpoint authN (gateway mode): everything except /healthz needs the bearer.
    if let Some(expected) = gateway.http_auth() {
        if path != "/healthz" && !bearer_ok(authorization.as_deref(), expected) {
            return respond(
                w,
                "401 Unauthorized",
                "text/plain",
                &[("WWW-Authenticate", "Bearer".to_string())],
                b"missing or invalid bearer token",
            );
        }
    }
    match method.as_str() {
        "GET" if path == "/healthz" => respond(w, "200 OK", "text/plain", &[], b"ok"),
        "GET" if path == "/metrics" => respond(
            w,
            "200 OK",
            "application/json",
            &[],
            gateway.metrics_json().as_bytes(),
        ),
        "GET" => respond(
            w,
            "405 Method Not Allowed",
            "text/plain",
            &[],
            b"use POST for JSON-RPC",
        ),
        "POST" if path == "/access/v1/evaluation" => {
            // AuthZEN PDP query (no token forwarding, no DPoP).
            let mut body = vec![0u8; content_length];
            reader.read_exact(&mut body)?;
            respond(
                w,
                "200 OK",
                "application/json",
                &[],
                gateway.authzen_evaluate(&body).as_bytes(),
            )
        }
        "POST" => {
            // DPoP sender-constraint (RFC 9449): if the session token is bound
            // to a key, every request must carry a valid proof for it.
            if let Some(jkt) = gateway.required_dpop_jkt() {
                let htu = format!("http://{host}{path}");
                let ok = dpop
                    .as_deref()
                    .map(|p| crate::dpop::verify_proof(p, "POST", &htu, &jkt, now_unix(), 30))
                    .transpose();
                match ok {
                    Ok(Some(())) => {}
                    _ => {
                        return respond(
                            w,
                            "401 Unauthorized",
                            "text/plain",
                            &[("DPoP-Nonce", String::new())],
                            b"DPoP proof required or invalid",
                        );
                    }
                }
            }
            let mut body = vec![0u8; content_length];
            reader.read_exact(&mut body)?;
            // The Authorization bearer carries the per-request delegation token
            // for shared-gateway identity (distinct from the optional endpoint
            // shared-secret `http_auth`, which isn't used on the loopback surface).
            let bearer = authorization
                .as_deref()
                .and_then(|a| {
                    a.strip_prefix("Bearer ")
                        .or_else(|| a.strip_prefix("bearer "))
                })
                .map(str::trim)
                .filter(|s| !s.is_empty());
            handle_rpc(w, &gateway, &body, bearer)
        }
        _ => respond(
            w,
            "405 Method Not Allowed",
            "text/plain",
            &[],
            b"unsupported method",
        ),
    }
}

fn handle_rpc(
    w: &TcpStream,
    gateway: &Gateway,
    body: &[u8],
    bearer: Option<&str>,
) -> std::io::Result<()> {
    // Support a single message or a JSON-RPC batch (array).
    let value: serde_json::Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => {
            let err = Response::error(None, -32700, format!("parse error: {e}"));
            return respond_json(w, "400 Bad Request", &err, &[]);
        }
    };

    if let serde_json::Value::Array(items) = value {
        let mut responses = Vec::new();
        for item in items {
            if let Ok(req) = serde_json::from_value::<Request>(item) {
                if req.id.is_some() {
                    responses.push(gateway.handle_request(&req, bearer));
                } else {
                    gateway.notify(&req);
                }
            }
        }
        if responses.is_empty() {
            return respond(w, "202 Accepted", "text/plain", &[], b"");
        }
        let body = serde_json::to_string(&responses).unwrap_or_default();
        return respond(w, "200 OK", "application/json", &[], body.as_bytes());
    }

    let req: Request = match serde_json::from_value(value) {
        Ok(r) => r,
        Err(e) => {
            let err = Response::error(None, -32600, format!("invalid request: {e}"));
            return respond_json(w, "400 Bad Request", &err, &[]);
        }
    };

    // Notifications (no id) get 202 and no body.
    if req.id.is_none() {
        gateway.notify(&req);
        return respond(w, "202 Accepted", "text/plain", &[], b"");
    }

    // On initialize, hand back a session id (MCP Streamable-HTTP convention).
    let extra: Vec<(&str, String)> = if req.method == "initialize" {
        let n = SESSION_SEQ.fetch_add(1, Ordering::Relaxed);
        vec![("Mcp-Session-Id", format!("sess-{}-{}", now_unix(), n))]
    } else {
        Vec::new()
    };

    let resp = gateway.handle_request(&req, bearer);
    respond_json(w, "200 OK", &resp, &extra)
}

fn respond_json(
    w: &TcpStream,
    status: &str,
    resp: &Response,
    extra: &[(&str, String)],
) -> std::io::Result<()> {
    let body = serde_json::to_string(resp).unwrap_or_default();
    respond(w, status, "application/json", extra, body.as_bytes())
}

/// Validate `Authorization: Bearer <token>` against the expected token in
/// constant time (avoid leaking the token via comparison timing).
fn bearer_ok(header: Option<&str>, expected: &str) -> bool {
    let Some(token) = header.and_then(|h| h.strip_prefix("Bearer ")) else {
        return false;
    };
    let (a, b) = (token.as_bytes(), expected.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn respond(
    mut w: &TcpStream,
    status: &str,
    content_type: &str,
    extra: &[(&str, String)],
    body: &[u8],
) -> std::io::Result<()> {
    write!(w, "HTTP/1.1 {status}\r\n")?;
    write!(w, "Content-Type: {content_type}\r\n")?;
    write!(w, "Content-Length: {}\r\n", body.len())?;
    for (k, v) in extra {
        write!(w, "{k}: {v}\r\n")?;
    }
    write!(w, "Connection: close\r\n\r\n")?;
    w.write_all(body)?;
    w.flush()
}
