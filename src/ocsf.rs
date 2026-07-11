//! OCSF event formatting -- emit each decision in the Open Cybersecurity Schema
//! Framework "API Activity" class (uid 6003) so it drops straight into a SIEM
//! (Splunk/Sentinel/Chronicle) with no custom parsing. OpenTelemetry resource
//! and trace fields ride in `metadata` for o11y correlation.

use crate::util::sha256_hex;
use serde_json::{json, Value};
use std::fs::OpenOptions;
use std::io::Write;

/// Build an OCSF API-Activity event for one decision.
#[allow(clippy::too_many_arguments)]
pub fn event(
    tool: &str,
    decision: &str,
    outcome: &str,
    latency_ms: u128,
    accountable: &str,
    agent: &str,
    act_chain: &[String],
    token_jti: &str,
    ts_unix: u64,
) -> Value {
    // status: Success for an executed allow, or an approved-then-executed call.
    // Parenthesised intent + prefix match: `contains("approved")` previously
    // mislabelled denials like an "unapproved" outcome as Success to the SIEM.
    let success =
        (decision == "allow" && outcome.starts_with("executed")) || outcome.starts_with("approved");
    let (status_id, status) = if success {
        (1, "Success")
    } else {
        (2, "Failure")
    };
    let severity_id = match decision {
        "allow" => 1,            // Informational
        "require_approval" => 2, // Low
        _ => 3,                  // Medium (deny / blocked / revoked / expired)
    };
    // OTel ids derived deterministically (no RNG): hash of the action context.
    let seed = format!("{token_jti}|{ts_unix}|{tool}|{outcome}");
    let h = sha256_hex(&seed);
    let trace_id = &h[..32];
    let span_id = &h[32..48];

    json!({
        "class_uid": 6003, "class_name": "API Activity",
        "category_uid": 6, "category_name": "Application Activity",
        "activity_id": 0, "type_uid": 600300,
        "time": ts_unix * 1000,
        "severity_id": severity_id,
        "status_id": status_id, "status": status, "status_detail": outcome,
        "actor": {
            "user": { "name": accountable, "type": "Human" },
            "process": { "name": agent },
            "invoked_by": act_chain.join(" > ")
        },
        "api": {
            "operation": tool,
            "service": { "name": "warden" }
        },
        "metadata": {
            "product": { "name": "Warden", "vendor_name": "Warden", "feature": { "name": "action-control-plane" } },
            "log_provider": "warden",
            "trace_id": trace_id,
            "span_id": span_id,
            "service.name": "warden"
        },
        "unmapped": {
            "decision": decision,
            "token_jti": token_jti,
            "latency_ms": latency_ms
        }
    })
}

/// Append an OCSF event (one JSON object per line) to the sink file.
pub fn append(path: &str, ev: &Value) {
    if let Some(parent) = std::path::Path::new(path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(f, "{ev}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ocsf_shape_for_a_denied_action() {
        let ev = event(
            "wire_funds",
            "deny",
            "blocked",
            2,
            "human:alice",
            "agent:bot",
            &["svc".into(), "agent:bot".into()],
            "tok1",
            100,
        );
        assert_eq!(ev["class_uid"], 6003);
        assert_eq!(ev["status"], "Failure");
        assert_eq!(ev["severity_id"], 3);
        assert_eq!(ev["api"]["operation"], "wire_funds");
        assert_eq!(ev["actor"]["user"]["name"], "human:alice");
        assert_eq!(ev["metadata"]["service.name"], "warden");
        assert_eq!(ev["metadata"]["trace_id"].as_str().unwrap().len(), 32);
    }
}
