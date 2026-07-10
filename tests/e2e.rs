//! End-to-end tests that drive the built `warden` binary as a black box.
//! No external services: the demo is self-contained, and proxy tests use the
//! deny path (which never touches the upstream) plus a no-op upstream.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_warden")
}

fn tmp(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("warden_e2e_{}_{}", std::process::id(), name));
    p
}

/// Run the binary with args (and optional stdin); return (stdout, stderr, ok).
fn run(args: &[&str], stdin: Option<&str>) -> (String, String, bool) {
    let mut cmd = Command::new(bin());
    cmd.args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn warden");
    if let Some(input) = stdin {
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
    }
    drop(child.stdin.take());
    let out = child.wait_with_output().expect("wait");
    (
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
        out.status.success(),
    )
}

#[test]
fn demo_runs_and_chain_verifies() {
    let dir = tmp("demo");
    let _ = std::fs::create_dir_all(&dir);
    // Demo writes .warden-demo in CWD; run it in a temp dir to avoid pollution.
    let mut cmd = Command::new(bin());
    cmd.arg("demo")
        .current_dir(&dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let out = cmd.output().expect("run demo");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("chain verified: OK"),
        "demo stdout:\n{stdout}"
    );

    // Verify the produced chain via the audit subcommand.
    let audit = dir.join(".warden-demo/audit.jsonl");
    let (o, _e, ok) = run(
        &["audit", "verify", "--audit", audit.to_str().unwrap()],
        None,
    );
    assert!(ok, "audit verify failed: {o}");
    assert!(o.contains("unbroken"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn audit_tamper_is_detected() {
    let dir = tmp("tamper");
    let _ = std::fs::create_dir_all(&dir);
    Command::new(bin())
        .arg("demo")
        .current_dir(&dir)
        .output()
        .expect("demo");
    let audit = dir.join(".warden-demo/audit.jsonl");

    // Flip a byte in the middle of the log, then expect verification to fail.
    let mut content = std::fs::read_to_string(&audit).unwrap();
    content = content.replacen("executed", "EXECUTED", 1);
    std::fs::write(&audit, content).unwrap();
    let (_o, _e, ok) = run(
        &["audit", "verify", "--audit", audit.to_str().unwrap()],
        None,
    );
    assert!(!ok, "tampered chain must fail verification");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn policy_lint_flags_errors() {
    let path = tmp("bad.policy.toml");
    std::fs::write(
        &path,
        r#"
        default = "allow"
        [[rules]]
        tool = "*"
        decision = "allow"
        [[rules]]
        tool = "x"
        when = { field = "bogus:y", op = "eq", value = "z" }
        decision = "deny"
    "#,
    )
    .unwrap();
    let (o, _e, ok) = run(
        &["policy", "lint", "--policy", path.to_str().unwrap()],
        None,
    );
    assert!(!ok, "lint should fail on the bad policy");
    assert!(o.contains("unreachable") && o.contains("unknown field namespace"));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn proxy_denies_by_default_without_touching_upstream() {
    let dir = tmp("deny");
    let _ = std::fs::create_dir_all(&dir);
    let policy = dir.join("p.toml");
    std::fs::write(&policy, "default = \"deny\"\n").unwrap();
    let audit = dir.join("a.jsonl");
    let appr = dir.join("ap.json");

    // `cat` is a harmless no-op upstream; denied calls never reach it. Also feed
    // a malformed line first to prove the parser skips junk without crashing.
    let input = "not json\n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"wire_funds\",\"arguments\":{}}}\n";
    let (o, _e, ok) = run(
        &[
            "proxy",
            "--upstream",
            "cat",
            "--agent",
            "t",
            "--policy",
            policy.to_str().unwrap(),
            "--audit",
            audit.to_str().unwrap(),
            "--approvals",
            appr.to_str().unwrap(),
        ],
        Some(input),
    );
    assert!(ok, "proxy exited nonzero");
    assert!(
        o.contains("BLOCKED by Warden"),
        "expected a block, got: {o}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn token_verify_conformance_dev_envelope() {
    // A dev-envelope token (no crypto) -- the conformance checker's happy path.
    let path = tmp("tok.json");
    std::fs::write(
        &path,
        r#"{ "claims": { "aud": "warden:test", "exp": 4102444800, "sub": "human:alice",
              "act": { "sub": "agent:bot" }, "scope": ["wire_funds"] } }"#,
    )
    .unwrap();
    let p = path.to_str().unwrap();
    let (o, _e, ok) = run(
        &[
            "token",
            "verify",
            "--token",
            p,
            "--aud",
            "warden:test",
            "--agent",
            "agent:bot",
        ],
        None,
    );
    assert!(ok, "valid token should verify: {o}");
    assert!(o.contains("accountable: human:alice"));

    // Wrong agent -> fails closed.
    let (_o, _e, bad) = run(
        &[
            "token",
            "verify",
            "--token",
            p,
            "--aud",
            "warden:test",
            "--agent",
            "agent:evil",
        ],
        None,
    );
    assert!(!bad, "actor mismatch must fail verification");
    let _ = std::fs::remove_file(&path);
}
