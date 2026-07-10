//! Warden -- an action control plane for AI agents.
//!
//! Sits as an MCP proxy between an agent and its tool servers: every `tools/call`
//! is checked against policy (allow / deny / require-approval), held for human
//! approval when required, and recorded in a tamper-evident audit chain.

use warden::{
    anchor, approval_sig, approvals, audit, budget, control, demo, gateway, http, identity,
    jsonrpc, policy, revocation, sink, upstream, util,
};

use approvals::{Approvals, Status};
use audit::AuditLog;
use control::{Control, ControlState};
use gateway::Gateway;
use jsonrpc::Request;
use policy::PolicyConfig;
use std::io::{BufRead, Write};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use util::now_unix;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("help");
    let result = match cmd {
        "demo" => {
            demo::run();
            Ok(())
        }
        "proxy" => run_proxy(&args[2..]),
        "audit" => run_audit(&args[2..]),
        "approvals" => run_approvals_list(&args[2..]),
        "approve" => resolve(&args[2..], Status::Approved),
        "deny" => resolve(&args[2..], Status::Denied),
        "pause" => run_control(&args[2..], ControlState::Paused),
        "resume" => run_control(&args[2..], ControlState::Running),
        "revoke" => run_revoke(&args[2..]),
        "token" => run_token(&args[2..]),
        "policy" => run_policy(&args[2..]),
        _ => {
            print_help();
            Ok(())
        }
    };
    if let Err(msg) = result {
        eprintln!("error: {msg}");
        std::process::exit(1);
    }
}

fn flag<'a>(args: &'a [String], name: &str, default: &'a str) -> &'a str {
    let mut i = 0;
    while i + 1 < args.len() {
        if args[i] == name {
            return &args[i + 1];
        }
        i += 1;
    }
    default
}

/// Proxy options loaded from a `[proxy]` table in a TOML config file. Flags
/// always win over config; config wins over built-in defaults.
struct Config(std::collections::BTreeMap<String, String>);

impl Config {
    fn empty() -> Self {
        Config(std::collections::BTreeMap::new())
    }

    fn load(path: &str) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("read config: {e}"))?;
        let val: toml::Value = toml::from_str(&text).map_err(|e| format!("invalid config: {e}"))?;
        let mut map = std::collections::BTreeMap::new();
        if let Some(tbl) = val.get("proxy").and_then(|v| v.as_table()) {
            for (k, v) in tbl {
                let s = match v {
                    toml::Value::String(s) => s.clone(),
                    toml::Value::Integer(i) => i.to_string(),
                    toml::Value::Boolean(b) => b.to_string(),
                    toml::Value::Float(f) => f.to_string(),
                    _ => continue,
                };
                map.insert(k.clone(), s);
            }
        }
        Ok(Config(map))
    }

    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).map(|s| s.as_str())
    }
}

/// The `WARDEN_*` environment variable for an option, e.g. `jwks-url` ->
/// `WARDEN_JWKS_URL`. This is the 12-factor config channel (factor III): every
/// option is settable from the environment, so the same build runs unchanged
/// across dev/staging/prod with only its env differing.
fn env_var(name: &str) -> Option<String> {
    let key = format!("WARDEN_{}", name.to_uppercase().replace('-', "_"));
    std::env::var(key).ok().filter(|s| !s.is_empty())
}

/// Resolve a string option. Precedence (highest first): CLI flag, `WARDEN_*`
/// environment variable, `[proxy]` config table, built-in default.
fn getopt(args: &[String], cfg: &Config, name: &str, default: &str) -> String {
    let flagname = format!("--{name}");
    let f = flag(args, &flagname, "\u{0}");
    if f != "\u{0}" {
        return f.to_string();
    }
    if let Some(v) = env_var(name) {
        return v;
    }
    cfg.get(name)
        .map(|s| s.to_string())
        .unwrap_or_else(|| default.to_string())
}

/// Resolve a boolean flag: present in args, `WARDEN_*` env set to a truthy
/// value, or `name = true` in config.
fn is_set(args: &[String], cfg: &Config, name: &str) -> bool {
    let flagname = format!("--{name}");
    let env_truthy = env_var(name)
        .map(|v| matches!(v.as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false);
    args.iter().any(|a| a == &flagname) || env_truthy || cfg.get(name) == Some("true")
}

/// Install signal handlers (Unix): SIGHUP -> reload policy; SIGTERM/SIGINT ->
/// graceful shutdown (stop accepting, drain in-flight).
#[cfg(unix)]
fn install_signals() {
    extern "C" fn handler(sig: libc::c_int) {
        if sig == libc::SIGHUP {
            gateway::request_reload();
        } else {
            http::request_shutdown();
        }
    }
    let ptr: extern "C" fn(libc::c_int) = handler;
    unsafe {
        libc::signal(libc::SIGHUP, ptr as usize as libc::sighandler_t);
        libc::signal(libc::SIGTERM, ptr as usize as libc::sighandler_t);
        libc::signal(libc::SIGINT, ptr as usize as libc::sighandler_t);
    }
}

#[cfg(not(unix))]
fn install_signals() {}

/// Real MCP proxy: stdin/stdout speak JSON-RPC with the agent; allowed calls
/// forward to the spawned upstream MCP server.
fn run_proxy(args: &[String]) -> Result<(), String> {
    // Options come from flags, then `WARDEN_*` env, then a `[proxy]` table in
    // --config (which itself may be set via WARDEN_CONFIG).
    let config_path = {
        let f = flag(args, "--config", "\u{0}");
        if f != "\u{0}" {
            f.to_string()
        } else {
            env_var("config").unwrap_or_default()
        }
    };
    let config = if config_path.is_empty() {
        Config::empty()
    } else {
        Config::load(&config_path)?
    };
    let get = |name: &str, default: &str| getopt(args, &config, name, default);

    let upstream_cmd = get("upstream", "");
    if upstream_cmd.is_empty() {
        return Err(
            "proxy requires --upstream \"<command>\" (or upstream= in --config)".to_string(),
        );
    }
    let agent = get("agent", "agent");
    let policy_path = get("policy", "warden.policy.toml");
    let audit_path = get("audit", ".warden/audit.jsonl");
    let approvals_path = get("approvals", ".warden/approvals.json");
    let token_path = get("token", "");
    let audience = get("aud", "");
    let issuer = get("iss", "");
    let jwks_path = get("jwks", "");
    let mut jwks_url = get("jwks-url", "");
    let issuer_url = get("issuer-url", "");
    // OIDC discovery: resolve jwks_uri from the issuer metadata if needed.
    if jwks_url.is_empty() && !issuer_url.is_empty() {
        jwks_url = identity::discover_jwks_uri(&issuer_url)?;
        eprintln!("warden: OIDC discovery -> jwks_uri {jwks_url}");
    }
    let issuer_key = get("issuer-key", "");
    let leeway = get("leeway", "60");
    let token_key = get("token-key", "");
    let control_path = get("control", "");
    let anchor_path = get("anchor", "");
    let anchor_key_path = get("anchor-key", "");
    let anchor_interval = get("anchor-interval", "1");
    let upstream_timeout = get("upstream-timeout", "30");
    let log_format = get("log-format", "text");
    let metrics_path = get("metrics", "");

    let policy = PolicyConfig::from_file(&policy_path)?;
    let mut audit = AuditLog::new(&audit_path);
    // Signed-checkpoint anchoring: sign the chain head to a separate file so
    // rewrites/rollbacks below a checkpoint are detectable.
    if !anchor_path.is_empty() {
        if anchor_key_path.is_empty() {
            return Err("--anchor requires --anchor-key <PEM>".to_string());
        }
        let key = std::fs::read(&anchor_key_path).map_err(|e| format!("read anchor key: {e}"))?;
        let interval = anchor_interval.parse().unwrap_or(1);
        audit.set_anchor(&key, &anchor_path, interval)?;
    }
    let approvals = Approvals::new(&approvals_path);
    let upstream = upstream::StdioUpstream::spawn(
        &upstream_cmd,
        Duration::from_secs(upstream_timeout.parse().unwrap_or(30)),
    )?;
    let mut gateway = Gateway::new(
        policy,
        audit,
        approvals,
        &agent,
        Box::new(upstream),
        Duration::from_secs(300),
    );
    gateway.set_policy_path(&policy_path);

    // Bind the verified session token (who the agent acts for), if provided.
    if !token_path.is_empty() {
        let some = |s: &str| (!s.is_empty()).then(|| s.to_string());
        let opts = identity::VerifyOpts {
            agent: agent.clone(),
            now: now_unix(),
            expected_aud: some(&audience),
            expected_iss: some(&issuer),
            leeway: leeway.parse().unwrap_or(60),
            jwks_path: some(&jwks_path),
            jwks_url: some(&jwks_url),
            pem_path: some(&issuer_key),
            dev_key: some(&token_key),
            require_at_jwt: is_set(args, &config, "require-at-jwt"),
        };
        let token = identity::load_and_verify(&token_path, &opts)?;
        eprintln!(
            "warden: token verified -- accountable {} via {} (mode: {}, signed: {})",
            token.claims.sub,
            token.claims.act_chain().join(" > "),
            if opts.jwks_path.is_some() || opts.pem_path.is_some() {
                "jwt"
            } else {
                "dev"
            },
            token.signed,
        );
        gateway.set_principal(token, &token_path, opts);
    }

    // Per-request identity (shared HTTP gateway): each `tools/call` carries its
    // own bearer delegation token, verified per call to the accountable human.
    // Unlike --token (one session principal), this attributes every call on a
    // gateway that serves many users. Combine with policy `require_identity` to
    // fail closed when a call arrives without a valid token.
    if is_set(args, &config, "request-identity") {
        let some = |s: &str| (!s.is_empty()).then(|| s.to_string());
        let opts = identity::VerifyOpts {
            agent: agent.clone(),
            now: now_unix(),
            expected_aud: some(&audience),
            expected_iss: some(&issuer),
            leeway: leeway.parse().unwrap_or(60),
            jwks_path: some(&jwks_path),
            jwks_url: some(&jwks_url),
            pem_path: some(&issuer_key),
            dev_key: some(&token_key),
            require_at_jwt: is_set(args, &config, "require-at-jwt"),
        };
        eprintln!(
            "warden: per-request identity ON -- verifying a bearer delegation token per tools/call"
        );
        gateway.set_request_verify(opts);
    }

    // Durable per-run budget (survives restarts), if a budget file is given.
    let budget_path = get("budget", "");
    if !budget_path.is_empty() {
        gateway.set_budget(budget::Budget::file(budget_path));
    }

    // Operational observability: structured JSON decision logs to stderr.
    if log_format == "json" {
        gateway.set_observability(true);
    }
    // OCSF event sink (SIEM-ready), if a path is given.
    let ocsf_path = get("ocsf", "");
    if !ocsf_path.is_empty() {
        gateway.set_ocsf(&ocsf_path);
    }
    // Require a bearer token on the HTTP surface (gateway mode).
    let http_auth = get("http-auth-token", "");
    if !http_auth.is_empty() {
        gateway.set_http_auth(&http_auth);
    }
    // PII/secret redaction of recorded & exported data (regulation profiles).
    let redact_profiles = get("redact", "");
    let redact_fields = get("redact-fields", "");
    if !redact_profiles.is_empty() || !redact_fields.is_empty() {
        let scan = is_set(args, &config, "redact-scan-values");
        gateway.set_redactor(warden::redact::Redactor::from_config(
            &redact_profiles,
            &redact_fields,
            scan,
        ));
    }
    // Transaction-Token minting on allow (call-context propagation for A2A).
    let txn_key = get("txn-key", "");
    if !txn_key.is_empty() {
        let pem = std::fs::read(&txn_key).map_err(|e| format!("read txn key: {e}"))?;
        gateway.set_txn_key(pem);
    }
    let txn_verify_key = get("txn-verify-key", "");
    if !txn_verify_key.is_empty() {
        let pem =
            std::fs::read(&txn_verify_key).map_err(|e| format!("read txn verify key: {e}"))?;
        gateway.set_txn_verify_key(pem);
    }

    // Standards-based sinks (format x transport x filter x delivery) from --config.
    let mut failsafe_sinks: Vec<sink::Sink> = Vec::new();
    if !config_path.is_empty() {
        let (blocking, failsafe): (Vec<_>, Vec<_>) = sink::load_specs(&config_path)?
            .into_iter()
            .partition(|s| s.delivery() == sink::Delivery::Blocking);
        if !blocking.is_empty() {
            eprintln!(
                "warden: {} high-assurance (blocking) sink(s)",
                blocking.len()
            );
            gateway.set_blocking_sinks(blocking);
        }
        failsafe_sinks = failsafe;
    }

    // Optionally require the MCP `initialize` handshake before any tools/call.
    if is_set(args, &config, "require-handshake") {
        gateway.set_require_handshake(true);
    }

    // Require signed approvals from an allowlisted approver key set, if given.
    let approver_jwks = get("approver-jwks", "");
    if !approver_jwks.is_empty() {
        let text = std::fs::read_to_string(&approver_jwks)
            .map_err(|e| format!("read approver jwks: {e}"))?;
        let keys =
            serde_json::from_str(&text).map_err(|e| format!("invalid approver jwks: {e}"))?;
        gateway.set_approver_keys(keys);
    }

    // Subscribe to a signed revocation feed (negative authority), if given.
    let revocations = get("revocations", "");
    let revocation_pub = get("revocation-pub", "");
    if !revocations.is_empty() {
        if revocation_pub.is_empty() {
            return Err("--revocations requires --revocation-pub <PEM>".to_string());
        }
        let pubkey =
            std::fs::read(&revocation_pub).map_err(|e| format!("read revocation pubkey: {e}"))?;
        gateway.set_revocations(revocation::RevocationSet::load(&revocations, &pubkey)?);
    }

    // Enable the admin pause/resume control plane, if a control file is given.
    if !control_path.is_empty() {
        gateway.set_control(Control::new(control_path), &policy_path);
    }

    // SIGHUP -> reload policy; SIGTERM/SIGINT -> graceful drain (Unix).
    install_signals();
    let drain_secs: u64 = get("drain-timeout", "10").parse().unwrap_or(10);

    // Share the gateway across worker threads. A request held for approval
    // blocks only its own worker, so other requests keep flowing. Responses are
    // correlated by JSON-RPC id, so out-of-order replies are fine.
    let gateway = Arc::new(gateway);

    // Fail-safe sinks tail the audit WAL off the hot path (decoupled, replayable).
    if !failsafe_sinks.is_empty() {
        eprintln!(
            "warden: {} fail-safe sink(s) tailing the audit log",
            failsafe_sinks.len()
        );
        let audit_tail = audit_path.clone();
        thread::spawn(move || forward_sinks(&audit_tail, failsafe_sinks));
    }

    // HTTP transport (MCP Streamable-HTTP), or stdio. Both drain before exit.
    let http_addr = get("http", "");
    if !http_addr.is_empty() {
        http::serve(&http_addr, gateway.clone(), drain_secs)?;
    } else {
        let stdout = Arc::new(Mutex::new(std::io::stdout()));
        let mut workers: Vec<thread::JoinHandle<()>> = Vec::new();

        let stdin = std::io::stdin();
        for line in stdin.lock().lines() {
            if http::shutting_down() {
                break; // SIGTERM/SIGINT between requests -> stop accepting
            }
            let line = line.map_err(|e| e.to_string())?;
            if line.trim().is_empty() {
                continue;
            }
            let req: Request = match serde_json::from_str(&line) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("warden: skipping unparseable line: {e}");
                    continue;
                }
            };
            if req.id.is_none() {
                // Notification: forward, no response expected.
                gateway.notify(&req);
                continue;
            }
            let gateway = gateway.clone();
            let stdout = stdout.clone();
            workers.push(thread::spawn(move || {
                let resp = gateway.handle_request(&req, None);
                if let Ok(line) = serde_json::to_string(&resp) {
                    let mut out = stdout.lock().unwrap();
                    let _ = writeln!(out, "{line}");
                    let _ = out.flush();
                }
            }));
        }

        // Drain in-flight workers (held approvals, slow upstream) before exit.
        for w in workers {
            let _ = w.join();
        }
    }

    // Sign a final checkpoint of the audit head, then report metrics.
    gateway.checkpoint_audit();
    let metrics = (!metrics_path.is_empty()).then_some(metrics_path.as_str());
    eprintln!("{}", gateway.report_metrics(metrics));
    Ok(())
}

/// Background fail-safe forwarder: tail the audit WAL by **byte offset** (O(new
/// bytes), not O(n) per tick) and ship new rows to the fail-safe sinks
/// (at-least-once, retry-with-backoff). A slow/down sink never touches the
/// action path -- at worst it lags. Only complete lines (up to the last newline)
/// are consumed, so a mid-write append is picked up on the next tick.
fn forward_sinks(audit_path: &str, sinks: Vec<sink::Sink>) {
    use std::io::{Read, Seek, SeekFrom};
    let mut offset: u64 = 0;
    loop {
        if let Ok(mut f) = std::fs::File::open(audit_path) {
            let len = f.metadata().map(|m| m.len()).unwrap_or(0);
            if len > offset && f.seek(SeekFrom::Start(offset)).is_ok() {
                let mut bytes = Vec::new();
                if f.read_to_end(&mut bytes).is_ok() {
                    if let Some(idx) = bytes.iter().rposition(|&b| b == b'\n') {
                        let consume = idx + 1;
                        let chunk = String::from_utf8_lossy(&bytes[..consume]);
                        for line in chunk.lines().filter(|l| !l.trim().is_empty()) {
                            let Ok(e) = serde_json::from_str::<audit::Entry>(line) else {
                                continue;
                            };
                            let ev = sink::SinkEvent::from_audit(&e);
                            for s in &sinks {
                                if !s.wants(&ev) {
                                    continue;
                                }
                                let mut ok = false;
                                for _ in 0..3 {
                                    if s.ship(&ev).is_ok() {
                                        ok = true;
                                        break;
                                    }
                                    thread::sleep(Duration::from_millis(200));
                                }
                                if !ok {
                                    eprintln!(
                                        "warden sink `{}`: dropped audit seq {}",
                                        s.name(),
                                        e.seq
                                    );
                                }
                            }
                        }
                        offset += consume as u64;
                    }
                }
            }
        }
        thread::sleep(Duration::from_millis(500));
    }
}

fn run_audit(args: &[String]) -> Result<(), String> {
    let sub = args.first().map(|s| s.as_str()).unwrap_or("verify");
    let audit_path = flag(args, "--audit", ".warden/audit.jsonl");
    let anchor_path = flag(args, "--anchor", "");
    let anchor_pub = flag(args, "--anchor-pub", "");
    let audit = AuditLog::new(audit_path);
    match sub {
        "verify" => {
            let n = audit
                .verify()
                .map_err(|msg| format!("audit chain BROKEN: {msg}"))?;
            println!("audit chain OK: {n} entries, unbroken");
            // Anchor verification catches rewrite/rollback the chain alone can't.
            if !anchor_path.is_empty() {
                if anchor_pub.is_empty() {
                    return Err("--anchor requires --anchor-pub <PEM>".to_string());
                }
                let pubkey =
                    std::fs::read(anchor_pub).map_err(|e| format!("read anchor pubkey: {e}"))?;
                let head: std::collections::HashMap<u64, String> = audit
                    .read_all()
                    .into_iter()
                    .map(|e| (e.seq, e.row_hash))
                    .collect();
                match anchor::verify(anchor_path, &pubkey, &head) {
                    Ok(c) => println!("anchor OK: {c} signed checkpoint(s) match the chain"),
                    Err(msg) => return Err(format!("ANCHOR VERIFICATION FAILED: {msg}")),
                }
            }
            Ok(())
        }
        "tail" => {
            for e in audit.read_all() {
                println!(
                    "#{:<3} {:<16} {:<16} {:<12} {}",
                    e.seq,
                    e.tool,
                    e.decision,
                    e.outcome,
                    &e.row_hash[..8]
                );
            }
            Ok(())
        }
        other => Err(format!("unknown audit subcommand: {other}")),
    }
}

fn run_approvals_list(args: &[String]) -> Result<(), String> {
    let approvals_path = flag(args, "--approvals", ".warden/approvals.json");
    let approvals = Approvals::new(approvals_path);
    let pending = approvals.list_pending();
    if pending.is_empty() {
        println!("no pending approvals");
    }
    for r in pending {
        println!(
            "{}  {} {}  ({})",
            r.id,
            r.tool,
            serde_json::to_string(&r.args).unwrap_or_default(),
            r.reason
        );
    }
    Ok(())
}

fn resolve(args: &[String], status: Status) -> Result<(), String> {
    let id = args
        .first()
        .ok_or("usage: warden approve|deny <id> [--approvals FILE]")?;
    let approvals_path = flag(args, "--approvals", ".warden/approvals.json");
    let approver = flag(args, "--by", "cli-user");
    let approver_key = flag(args, "--approver-key", "");
    let approvals = Approvals::new(approvals_path);

    // When approving with a key, sign an assertion binding the approver to this
    // exact action (id is the agent+tool+args fingerprint).
    let assertion = if status == Status::Approved && !approver_key.is_empty() {
        let pem = std::fs::read(approver_key).map_err(|e| format!("read approver key: {e}"))?;
        Some(approval_sig::sign(&pem, approver, id, now_unix())?)
    } else {
        None
    };
    approvals.set_status(id, status, approver, assertion.as_deref())?;
    println!(
        "{id}: {:?}{}",
        status,
        if assertion.is_some() { " (signed)" } else { "" }
    );
    Ok(())
}

/// Token conformance checker: verify a token the way the proxy would, and print
/// what Warden extracted. Adapters/SDKs run this against their output. Exits
/// nonzero if the token does not verify.
fn run_token(args: &[String]) -> Result<(), String> {
    if args.first().map(|s| s.as_str()) != Some("verify") {
        return Err(
            "usage: warden token verify --token FILE [--aud ..] [--agent ..] ...".to_string(),
        );
    }
    let token_path = flag(args, "--token", "");
    if token_path.is_empty() {
        return Err("token verify requires --token FILE".to_string());
    }
    let some = |s: &str| (!s.is_empty()).then(|| s.to_string());
    let opts = identity::VerifyOpts {
        agent: flag(args, "--agent", "agent").to_string(),
        now: now_unix(),
        expected_aud: some(flag(args, "--aud", "")),
        expected_iss: some(flag(args, "--iss", "")),
        leeway: flag(args, "--leeway", "60").parse().unwrap_or(60),
        jwks_path: some(flag(args, "--jwks", "")),
        jwks_url: some(flag(args, "--jwks-url", "")),
        pem_path: some(flag(args, "--issuer-key", "")),
        dev_key: some(flag(args, "--token-key", "")),
        require_at_jwt: args.iter().any(|a| a == "--require-at-jwt"),
    };
    let token = identity::load_and_verify(token_path, &opts)?;
    let c = &token.claims;
    println!("token OK");
    println!("  accountable: {}", c.sub);
    println!("  chain:       {}", c.act_chain().join(" > "));
    println!("  signed:      {}", token.signed);
    println!("  roles:       {}", c.roles.join(", "));
    println!("  scope:       {}", c.scope.join(", "));
    println!(
        "  relations:   {}",
        c.rel_pairs()
            .iter()
            .map(|(r, x)| format!("{r}@{x}"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    Ok(())
}

fn run_revoke(args: &[String]) -> Result<(), String> {
    let feed = flag(args, "--feed", ".warden/revocations.jsonl");
    let key_path = flag(args, "--revoke-key", "");
    if key_path.is_empty() {
        return Err("revoke requires --revoke-key <PEM> (the admin signing key)".to_string());
    }
    let (kind, subject) = if !flag(args, "--jti", "").is_empty() {
        ("jti", flag(args, "--jti", ""))
    } else if !flag(args, "--agent", "").is_empty() {
        ("agent", flag(args, "--agent", ""))
    } else if !flag(args, "--human", "").is_empty() {
        ("human", flag(args, "--human", ""))
    } else {
        return Err("revoke requires one of --jti, --agent, or --human".to_string());
    };
    let key = std::fs::read(key_path).map_err(|e| format!("read revoke key: {e}"))?;
    revocation::append(feed, &key, kind, subject, now_unix())?;
    println!("revoked {kind}={subject} (appended to {feed})");
    Ok(())
}

fn run_control(args: &[String], state: ControlState) -> Result<(), String> {
    let control_path = flag(args, "--control", ".warden/control");
    Control::set(control_path, state)?;
    println!("warden control: {} ({control_path})", state.as_str());
    if state == ControlState::Running {
        println!("(a running proxy watching this file will reload policy on resume)");
    }
    Ok(())
}

fn run_policy(args: &[String]) -> Result<(), String> {
    match args.first().map(|s| s.as_str()).unwrap_or("show") {
        "show" => run_policy_show(args),
        "lint" => run_policy_lint(args),
        "test" => run_policy_test(args),
        other => Err(format!(
            "unknown policy subcommand: {other} (show|lint|test)"
        )),
    }
}

fn run_policy_show(args: &[String]) -> Result<(), String> {
    let policy_path = flag(args, "--policy", "warden.policy.toml");
    let policy = PolicyConfig::from_file(policy_path)?;
    println!("default: {}", policy.default.as_str());
    println!("require_identity: {}", policy.require_identity);
    for r in &policy.rules {
        let mut gates = Vec::new();
        if let Some(role) = &r.require_role {
            gates.push(format!("role={role}"));
        }
        if let Some(rel) = &r.require_relation {
            gates.push(format!("rel={}@{}", rel.relation, rel.resource_arg));
        }
        if let Some(when) = &r.when {
            gates.push(format!("when[{}]", when.describe()));
        }
        let suffix = if gates.is_empty() {
            String::new()
        } else {
            format!("  ({})", gates.join(" "))
        };
        println!("  {} -> {}{}", r.tool, r.decision.as_str(), suffix);
    }
    Ok(())
}

fn run_policy_lint(args: &[String]) -> Result<(), String> {
    let policy_path = flag(args, "--policy", "warden.policy.toml");
    let policy = PolicyConfig::from_file(policy_path)?;
    let report = policy.lint();
    for w in &report.warnings {
        println!("WARN  {w}");
    }
    for e in &report.errors {
        println!("ERROR {e}");
    }
    if report.errors.is_empty() {
        println!(
            "policy OK: {} rule(s), {} warning(s)",
            policy.rules.len(),
            report.warnings.len()
        );
        Ok(())
    } else {
        Err(format!(
            "policy lint failed: {} error(s)",
            report.errors.len()
        ))
    }
}

/// Dry-run: evaluate a tool call against the policy without executing anything.
fn run_policy_test(args: &[String]) -> Result<(), String> {
    let policy_path = flag(args, "--policy", "warden.policy.toml");
    let tool = flag(args, "--tool", "");
    if tool.is_empty() {
        return Err("policy test requires --tool NAME [--args JSON]".to_string());
    }
    let args_json = flag(args, "--args", "{}");
    let call_args: serde_json::Value =
        serde_json::from_str(args_json).map_err(|e| format!("invalid --args JSON: {e}"))?;
    let policy = PolicyConfig::from_file(policy_path)?;

    // Build the subject from a token if one is supplied, else unauthenticated.
    let token_path = flag(args, "--token", "");
    let subject = if token_path.is_empty() {
        policy::Subject::default()
    } else {
        let some = |s: &str| (!s.is_empty()).then(|| s.to_string());
        let opts = identity::VerifyOpts {
            agent: flag(args, "--agent", "agent").to_string(),
            now: now_unix(),
            expected_aud: some(flag(args, "--aud", "")),
            expected_iss: some(flag(args, "--iss", "")),
            leeway: flag(args, "--leeway", "60").parse().unwrap_or(60),
            jwks_path: some(flag(args, "--jwks", "")),
            jwks_url: some(flag(args, "--jwks-url", "")),
            pem_path: some(flag(args, "--issuer-key", "")),
            dev_key: some(flag(args, "--token-key", "")),
            require_at_jwt: false,
        };
        let c = identity::load_and_verify(token_path, &opts)?.claims;
        policy::Subject {
            authenticated: true,
            roles: c.roles.clone(),
            attrs: c.attrs.clone(),
            rel: c.rel_pairs(),
            scope: c.scope.clone(),
            resource_attrs: c.resource_attrs.clone(),
        }
    };

    let env = serde_json::Map::new();
    let res = policy.evaluate(
        tool,
        &call_args,
        &subject,
        &env,
        &std::collections::HashMap::new(),
    );
    println!("tool:     {tool}");
    println!("decision: {}", res.decision.as_str());
    println!("trace:    {}", res.trace);
    println!("reason:   {}", res.reason);
    Ok(())
}

fn print_help() {
    println!(
        r#"warden -- action control plane for AI agents

USAGE:
  warden demo                     Run the self-contained walkthrough (no API key)
  warden proxy [--config FILE]    (a [proxy] TOML table; flags override it)
  warden proxy --upstream "<cmd>" [--agent NAME] [--policy FILE]
              [--token FILE [--aud AUD] [--iss ISS] [--leeway SECS]
                            (--jwks FILE | --issuer-key PEM | --token-key KEY)]
              [--control FILE]
              [--anchor FILE --anchor-key PEM [--anchor-interval N]]
              [--approver-jwks FILE] [--budget FILE] [--upstream-timeout SECS]
              [--require-handshake] [--log-format json] [--metrics FILE]
              [--http ADDR]
                                  Run as an MCP proxy (stdio, or HTTP with --http ADDR)
  warden approvals list           List pending held actions
  warden approve <id> [--by WHO] [--approver-key PEM]
                                  Approve a held action (signs a per-action assertion if a key is given)
  warden deny <id> [--by WHO]     Deny a held action
  warden pause  [--control FILE]  Pause the agent at Warden (stops forwarding)
  warden resume [--control FILE]  Resume; a running proxy reloads policy on resume
  warden revoke (--jti X | --agent Y | --human Z) --revoke-key PEM [--feed FILE]
                                  Append a signed revocation event to the feed
  warden token verify --token FILE [--aud AUD] [--agent NAME] (--jwks F|--issuer-key PEM|--token-key K)
                                  Verify a token (conformance check); prints the chain
  warden audit tail               Show the audit trail
  warden audit verify [--anchor FILE --anchor-pub PEM]
                                  Verify the chain (and signed checkpoints, if given)
  warden policy show              Show the loaded policy
  warden policy lint              Statically validate the policy (unreachable rules, bad fields)
  warden policy test --tool NAME [--args JSON] [--token FILE ...]
                                  Dry-run a tool call: print decision/trace without executing

Identity: --token is a signed session token (RFC 8693 delegation: sub=accountable
human, act=acting chain). Warden verifies aud/exp/actor and trusts the carried
roles/attrs/relationships. See docs/accountable-authorization.md.

Defaults: policy=warden.policy.toml  audit=.warden/audit.jsonl  approvals=.warden/approvals.json
          control=.warden/control
"#
    );
}
