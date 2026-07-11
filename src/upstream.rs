//! The upstream the proxy forwards allowed calls to. Two implementations:
//!   - `StdioUpstream`: a real MCP server spawned as a subprocess (the proxy use).
//!   - `DemoUpstream`: an in-process MCP server with toy tools (the demo).

use crate::jsonrpc::{Request, Response};
use crate::mcp::{parse_tool_call, tool_error_result, tool_text_result};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

pub trait Upstream {
    /// Forward a request and return its response.
    fn request(&mut self, req: &Request) -> Response;
    /// Forward a notification (no response expected).
    fn notify(&mut self, _req: &Request) {}
}

/// A live child process plus its pipes. Replaced wholesale on restart.
struct Child0 {
    child: Child,
    stdin: ChildStdin,
    reader: Option<BufReader<ChildStdout>>,
}

/// Upper bound on a single upstream response line (bytes). Generous for real
/// tool output; caps a runaway/hostile upstream so it can't OOM the proxy.
const MAX_UPSTREAM_LINE: usize = 8 * 1024 * 1024;

/// Read one `\n`-terminated line, but never buffer more than `cap` bytes. On a
/// line that exceeds the cap we stop and return what we have (which will fail to
/// parse as JSON -> a clean upstream error), rather than growing without bound.
fn read_line_capped<R: BufRead>(r: &mut R, cap: usize) -> (std::io::Result<usize>, String) {
    let mut raw: Vec<u8> = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match r.read(&mut byte) {
            Ok(0) => break, // EOF
            Ok(_) => {
                raw.push(byte[0]);
                if byte[0] == b'\n' || raw.len() >= cap {
                    break;
                }
            }
            Err(e) => return (Err(e), String::from_utf8_lossy(&raw).into_owned()),
        }
    }
    (Ok(raw.len()), String::from_utf8_lossy(&raw).into_owned())
}

/// A real MCP server over stdio (newline-delimited JSON-RPC), resilient to
/// upstream crashes and hangs: each call is bounded by a timeout, and the child
/// is restarted on crash or timeout so the next call works.
pub struct StdioUpstream {
    command: String,
    timeout: Duration,
    inner: Option<Child0>,
}

impl StdioUpstream {
    pub fn spawn(command: &str, timeout: Duration) -> Result<Self, String> {
        let inner = Self::launch(command)?;
        Ok(StdioUpstream {
            command: command.to_string(),
            timeout,
            inner: Some(inner),
        })
    }

    fn launch(command: &str) -> Result<Child0, String> {
        let mut parts = command.split_whitespace();
        let program = parts.next().ok_or("empty upstream command")?;
        let args: Vec<&str> = parts.collect();
        let mut child = Command::new(program)
            .args(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|e| format!("spawn upstream: {e}"))?;
        let stdin = child.stdin.take().ok_or("no upstream stdin")?;
        let stdout = child.stdout.take().ok_or("no upstream stdout")?;
        Ok(Child0 {
            child,
            stdin,
            reader: Some(BufReader::new(stdout)),
        })
    }

    /// Kill the current child (if any) and start a fresh one.
    fn restart(&mut self) {
        if let Some(inner) = &mut self.inner {
            let _ = inner.child.kill();
            let _ = inner.child.wait();
        }
        match Self::launch(&self.command) {
            Ok(inner) => {
                self.inner = Some(inner);
                eprintln!("warden: upstream restarted");
            }
            Err(e) => {
                self.inner = None;
                eprintln!("warden: upstream restart failed: {e}");
            }
        }
    }
}

impl Upstream for StdioUpstream {
    fn request(&mut self, req: &Request) -> Response {
        if self.inner.is_none() {
            self.restart();
        }
        let Some(inner) = &mut self.inner else {
            return Response::error(req.id.clone(), -32000, "upstream unavailable");
        };

        // Send the request.
        let line = match serde_json::to_string(req) {
            Ok(l) => l,
            Err(e) => return Response::error(req.id.clone(), -32603, format!("encode: {e}")),
        };
        if writeln!(inner.stdin, "{line}")
            .and_then(|_| inner.stdin.flush())
            .is_err()
        {
            self.restart();
            return Response::error(req.id.clone(), -32000, "upstream send failed; restarted");
        }

        // Read the response in a worker thread, bounded by the timeout. On
        // timeout we kill the child to unblock that read, then restart.
        let mut reader = match inner.reader.take() {
            Some(r) => r,
            None => {
                self.restart();
                return Response::error(req.id.clone(), -32000, "upstream reader lost; restarted");
            }
        };
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            // Bounded read: a hostile/buggy upstream streaming an unterminated
            // line could otherwise grow `buf` without limit (OOM) within the
            // timeout window. Cap it; a truncated line simply fails to parse.
            let (res, buf) = read_line_capped(&mut reader, MAX_UPSTREAM_LINE);
            let _ = tx.send((reader, res, buf));
        });

        match rx.recv_timeout(self.timeout) {
            Ok((reader, Ok(0), _)) => {
                if let Some(inner) = &mut self.inner {
                    inner.reader = Some(reader);
                }
                self.restart();
                Response::error(req.id.clone(), -32000, "upstream closed; restarted")
            }
            Ok((reader, Ok(_), buf)) => {
                if let Some(inner) = &mut self.inner {
                    inner.reader = Some(reader);
                }
                serde_json::from_str(buf.trim()).unwrap_or_else(|e| {
                    Response::error(
                        req.id.clone(),
                        -32000,
                        format!("bad upstream response: {e}"),
                    )
                })
            }
            Ok((reader, Err(e), _)) => {
                if let Some(inner) = &mut self.inner {
                    inner.reader = Some(reader);
                }
                self.restart();
                Response::error(
                    req.id.clone(),
                    -32000,
                    format!("upstream read failed: {e}; restarted"),
                )
            }
            Err(_) => {
                // Timed out: the read thread is still blocked. Killing the child
                // unblocks it; the orphaned thread then exits on its own.
                self.restart();
                Response::error(
                    req.id.clone(),
                    -32000,
                    format!(
                        "upstream timed out after {}s; restarted",
                        self.timeout.as_secs()
                    ),
                )
            }
        }
    }

    fn notify(&mut self, req: &Request) {
        if let Some(inner) = &mut self.inner {
            if let Ok(line) = serde_json::to_string(req) {
                let _ = writeln!(inner.stdin, "{line}").and_then(|_| inner.stdin.flush());
            }
        }
    }
}

/// In-process MCP server with toy tools, used by `warden demo`.
pub struct DemoUpstream;

impl Default for DemoUpstream {
    fn default() -> Self {
        Self::new()
    }
}

impl DemoUpstream {
    pub fn new() -> Self {
        DemoUpstream
    }

    fn call_tool(&self, name: &str, args: &Value) -> Value {
        match name {
            "list_directory" => {
                let path = args.get("path").and_then(|v| v.as_str()).unwrap_or(".");
                tool_text_result(format!("{path}: README.md  notes.txt  data/"))
            }
            "read_file" => {
                let path = args.get("path").and_then(|v| v.as_str()).unwrap_or("file");
                tool_text_result(format!("<contents of {path}>"))
            }
            "write_file" => {
                let path = args.get("path").and_then(|v| v.as_str()).unwrap_or("file");
                tool_text_result(format!("wrote {path}"))
            }
            "wire_funds" => {
                let to = args.get("to").and_then(|v| v.as_str()).unwrap_or("?");
                let amount = args.get("amount").and_then(|v| v.as_f64()).unwrap_or(0.0);
                tool_text_result(format!("wired ${amount} to {to}"))
            }
            "delete_database" => {
                let db = args.get("name").and_then(|v| v.as_str()).unwrap_or("?");
                tool_text_result(format!("DROPPED database {db}"))
            }
            "send_email" => {
                let to = args.get("to").and_then(|v| v.as_str()).unwrap_or("?");
                tool_text_result(format!("email sent to {to}"))
            }
            other => tool_error_result(format!("unknown tool: {other}")),
        }
    }
}

impl Upstream for DemoUpstream {
    fn request(&mut self, req: &Request) -> Response {
        match req.method.as_str() {
            "initialize" => Response::ok(
                req.id.clone(),
                json!({
                    "protocolVersion": "2024-11-05",
                    "serverInfo": { "name": "warden-demo-tools", "version": "0.1.0" },
                    "capabilities": { "tools": {} }
                }),
            ),
            "tools/list" => Response::ok(
                req.id.clone(),
                json!({ "tools": [
                    { "name": "list_directory", "description": "List a directory" },
                    { "name": "read_file", "description": "Read a file" },
                    { "name": "write_file", "description": "Write a file" },
                    { "name": "wire_funds", "description": "Transfer money" },
                    { "name": "delete_database", "description": "Drop a database" },
                    { "name": "send_email", "description": "Send an email" }
                ]}),
            ),
            "tools/call" => match parse_tool_call(&req.params) {
                Some((name, args)) => Response::ok(req.id.clone(), self.call_tool(&name, &args)),
                None => Response::error(req.id.clone(), -32602, "invalid tools/call params"),
            },
            _ => Response::ok(req.id.clone(), json!({})),
        }
    }
}
