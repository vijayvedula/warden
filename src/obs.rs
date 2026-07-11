//! Operational observability: structured decision logs + counters.
//!
//! Distinct from the audit log (which is the tamper-evident record of actions):
//! this is lightweight telemetry for operators -- per-decision JSON log lines
//! with latency, and rolling counters by decision/outcome surfaced as a metrics
//! snapshot. No external dependencies; emits to stderr / a JSON file.

use crate::util::now_unix;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

pub struct Obs {
    json: bool,
    total: AtomicU64,
    counts: Mutex<BTreeMap<String, u64>>,
}

impl Obs {
    pub fn new(json: bool) -> Self {
        Obs {
            json,
            total: AtomicU64::new(0),
            counts: Mutex::new(BTreeMap::new()),
        }
    }

    /// Record one decision: bump counters and (in JSON mode) emit a log line.
    #[allow(clippy::too_many_arguments)]
    pub fn record(
        &self,
        tool: &str,
        decision: &str,
        outcome: &str,
        latency: Duration,
        accountable: &str,
        token_jti: &str,
    ) {
        self.total.fetch_add(1, Ordering::Relaxed);
        {
            let mut c = self.counts.lock().unwrap();
            *c.entry(format!("decision.{decision}")).or_insert(0) += 1;
            *c.entry(format!("outcome.{outcome}")).or_insert(0) += 1;
        }
        if self.json {
            // One structured line per decision, with OpenTelemetry resource +
            // trace fields for o11y correlation.
            let h = crate::util::sha256_hex(&format!("{token_jti}|{}|{tool}", now_unix()));
            eprintln!(
                "{{\"ts\":{},\"ev\":\"decision\",\"service.name\":\"warden\",\"trace_id\":\"{}\",\"span_id\":\"{}\",\"tool\":{},\"decision\":{},\"outcome\":{},\"latency_ms\":{},\"accountable\":{},\"jti\":{}}}",
                now_unix(),
                &h[..32],
                &h[32..48],
                json_str(tool),
                json_str(decision),
                json_str(outcome),
                latency.as_millis(),
                json_str(accountable),
                json_str(token_jti),
            );
        }
    }

    pub fn total(&self) -> u64 {
        self.total.load(Ordering::Relaxed)
    }

    pub fn snapshot(&self) -> BTreeMap<String, u64> {
        self.counts.lock().unwrap().clone()
    }

    /// A compact one-line summary for shutdown.
    pub fn summary_line(&self) -> String {
        let counts = self.snapshot();
        let parts: Vec<String> = counts.iter().map(|(k, v)| format!("{k}={v}")).collect();
        format!("warden metrics: total={} {}", self.total(), parts.join(" "))
    }

    /// Write a JSON metrics snapshot to `path`.
    pub fn write_metrics(&self, path: &str) {
        let counts = self.snapshot();
        let body: serde_json::Map<String, serde_json::Value> = counts
            .into_iter()
            .map(|(k, v)| (k, serde_json::Value::from(v)))
            .collect();
        let doc = serde_json::json!({
            "ts": now_unix(),
            "total": self.total(),
            "counts": body,
        });
        if let Some(parent) = std::path::Path::new(path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(path, doc.to_string());
    }
}

/// Minimal JSON string escaping for log fields.
fn json_str(s: &str) -> String {
    serde_json::Value::from(s).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_accumulate() {
        let obs = Obs::new(false);
        obs.record(
            "wire_funds",
            "allow",
            "executed",
            Duration::from_millis(3),
            "human:a",
            "t1",
        );
        obs.record(
            "wire_funds",
            "deny",
            "blocked",
            Duration::from_millis(1),
            "human:a",
            "t1",
        );
        obs.record(
            "send_email",
            "allow",
            "executed",
            Duration::from_millis(2),
            "human:a",
            "t1",
        );
        assert_eq!(obs.total(), 3);
        let snap = obs.snapshot();
        assert_eq!(snap.get("decision.allow"), Some(&2));
        assert_eq!(snap.get("outcome.executed"), Some(&2));
        assert_eq!(snap.get("decision.deny"), Some(&1));
    }
}
