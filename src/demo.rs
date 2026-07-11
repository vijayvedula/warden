//! `warden demo` -- a self-contained, no-API-key walkthrough.
//!
//! Drives a simulated agent through a sequence of MCP tool calls against the
//! in-process demo server, with a background "reviewer" standing in for a human.
//! Shows: allow, budget, deny, and hold-for-approval (approved and denied),
//! then prints the tamper-evident audit trail and verifies the chain.

use crate::approvals::{Approvals, Status};
use crate::audit::AuditLog;
use crate::gateway::Gateway;
use crate::jsonrpc::{Request, Response};
use crate::policy::PolicyConfig;
use crate::upstream::DemoUpstream;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

const DEMO_POLICY: &str = r#"
default = "allow"

[[rules]]
tool = "delete_database"
decision = "deny"
reason = "destructive: agents may not drop databases"

[[rules]]
tool = "wire_funds"
when = { arg = "amount", op = "gt", value = 1000 }
decision = "require_approval"
reason = "financial action over $1000 requires human approval"

[[rules]]
tool = "send_email"
decision = "require_approval"
reason = "outbound email requires human approval"

[[rules]]
tool = "write_file"
decision = "allow"
max_per_run = 5
"#;

pub fn run() {
    let dir = PathBuf::from(".warden-demo");
    let _ = std::fs::create_dir_all(&dir);
    let audit_path = dir.join("audit.jsonl");
    let approvals_path = dir.join("approvals.json");
    let _ = std::fs::remove_file(&audit_path);
    let _ = std::fs::remove_file(&approvals_path);

    let policy = PolicyConfig::from_str(DEMO_POLICY).expect("valid demo policy");
    let audit = AuditLog::new(&audit_path);
    let approvals = Approvals::new(&approvals_path);

    // Background "human" reviewer: approves money transfers, blocks emails.
    let stop = Arc::new(AtomicBool::new(false));
    let reviewer = {
        let approvals = approvals.clone();
        let stop = stop.clone();
        std::thread::spawn(move || reviewer_loop(approvals, stop))
    };

    let gateway = Gateway::new(
        policy,
        audit,
        approvals.clone(),
        "demo-agent",
        Box::new(DemoUpstream::new()),
        Duration::from_secs(5),
    );

    println!("\n=== Warden demo -- agent action control plane ===");
    println!("policy: deny delete_database / approve wire_funds>$1000 / approve send_email / budget write_file=5\n");

    let script: Vec<(&str, Value, &str)> = vec![
        (
            "list_directory",
            json!({ "path": "." }),
            "agent inspects the workspace",
        ),
        (
            "read_file",
            json!({ "path": "README.md" }),
            "agent reads a file",
        ),
        (
            "write_file",
            json!({ "path": "notes.txt", "content": "todo" }),
            "agent writes a file",
        ),
        (
            "wire_funds",
            json!({ "to": "acct-123", "amount": 50 }),
            "small transfer (under threshold)",
        ),
        (
            "wire_funds",
            json!({ "to": "acct-999", "amount": 5000 }),
            "large transfer (needs approval)",
        ),
        (
            "delete_database",
            json!({ "name": "prod" }),
            "agent tries something destructive",
        ),
        (
            "send_email",
            json!({ "to": "ceo@example.com", "subject": "hi" }),
            "agent tries to email externally",
        ),
    ];

    for (id, (tool, args, note)) in (1i64..).zip(script) {
        println!("> {note}");
        println!("  call: {tool}({})", compact(&args));
        let req = Request::new(id, "tools/call", json!({ "name": tool, "arguments": args }));
        let out = gateway.handle_tool_call(&req, tool, &json_args(&req), None);
        let (text, is_error) = result_text(&out.response);
        let marker = decision_marker(out.decision.as_str(), is_error);
        println!("  {marker} [{}] {}", out.outcome, text);
        println!();
    }

    stop.store(true, Ordering::SeqCst);
    let _ = reviewer.join();

    print_audit(&AuditLog::new(&audit_path));
    println!(
        "\nfiles: {} / {}",
        audit_path.display(),
        approvals_path.display()
    );
    println!(
        "try:   warden audit verify --audit {}",
        audit_path.display()
    );
    println!("       (edit a line in audit.jsonl, then re-run verify to see tamper detection)\n");
}

fn reviewer_loop(approvals: Approvals, stop: Arc<AtomicBool>) {
    while !stop.load(Ordering::SeqCst) {
        for record in approvals.list_pending() {
            let (status, who) = match record.tool.as_str() {
                "wire_funds" => (Status::Approved, "alice (finance)"),
                "send_email" => (Status::Denied, "bob (security)"),
                _ => (Status::Approved, "auto"),
            };
            let _ = approvals.set_status(&record.id, status, who, None);
        }
        std::thread::sleep(Duration::from_millis(120));
    }
}

fn json_args(req: &Request) -> Value {
    req.params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}))
}

fn compact(v: &Value) -> String {
    serde_json::to_string(v).unwrap_or_default()
}

fn result_text(resp: &Response) -> (String, bool) {
    let Some(result) = &resp.result else {
        let msg = resp
            .error
            .as_ref()
            .map(|e| e.message.clone())
            .unwrap_or_else(|| "(no result)".to_string());
        return (msg, true);
    };
    let is_error = result
        .get("isError")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let text = result
        .get("content")
        .and_then(|c| c.get(0))
        .and_then(|c| c.get("text"))
        .and_then(|t| t.as_str())
        .unwrap_or("")
        .to_string();
    (text, is_error)
}

fn decision_marker(decision: &str, is_error: bool) -> &'static str {
    match (decision, is_error) {
        ("allow", false) => "[x] ALLOW   ",
        ("deny", _) => "x DENY    ",
        ("require_approval", false) => "[x] APPROVED",
        ("require_approval", true) => "x HELD    ",
        _ => "/         ",
    }
}

fn print_audit(audit: &AuditLog) {
    println!("=== tamper-evident audit trail (black-box recorder) ===");
    for e in audit.read_all() {
        let approver = e
            .approver
            .as_deref()
            .map(|a| format!(" by {a}"))
            .unwrap_or_default();
        println!(
            "  #{:<2} {:<16} {:<16} -> {:<10}{}  [{}...]",
            e.seq,
            e.tool,
            e.decision,
            e.outcome,
            approver,
            &e.row_hash[..8]
        );
    }
    match audit.verify() {
        Ok(n) => println!("\n  chain verified: OK ({n} entries, unbroken)"),
        Err(msg) => println!("\n  chain verification FAILED: {msg}"),
    }
}
