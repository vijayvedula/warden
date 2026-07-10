//! Per-run budget counters (the `max_per_run` caps in policy).
//!
//! In-memory counts reset on restart -- which lets an agent bypass a budget by
//! restarting the proxy. When a budget file is configured, counts are loaded at
//! startup and persisted on every increment, so a "run" survives restarts. The
//! file is the source of truth; deleting it (or not configuring one) starts a
//! fresh run. Single-writer per run, like the audit log.

use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

pub struct Budget {
    path: Option<PathBuf>,
    counts: Mutex<HashMap<String, u32>>,
}

impl Budget {
    /// In-memory budget (counts lost on restart).
    pub fn memory() -> Self {
        Budget {
            path: None,
            counts: Mutex::new(HashMap::new()),
        }
    }

    /// Durable budget backed by a JSON file (loaded now, saved on increment).
    pub fn file(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let counts = std::fs::read_to_string(&path)
            .ok()
            .and_then(|t| serde_json::from_str::<HashMap<String, u32>>(&t).ok())
            .unwrap_or_default();
        Budget {
            path: Some(path),
            counts: Mutex::new(counts),
        }
    }

    /// A snapshot of current counts, for policy evaluation.
    pub fn snapshot(&self) -> HashMap<String, u32> {
        self.counts.lock().unwrap().clone()
    }

    /// Increment usage for `tool` and persist. Returns the new count.
    pub fn increment(&self, tool: &str) -> u32 {
        let mut counts = self.counts.lock().unwrap();
        let n = counts.entry(tool.to_string()).or_insert(0);
        *n += 1;
        let new = *n;
        if let Some(path) = &self.path {
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _ = std::fs::write(
                path,
                Value::from(
                    counts
                        .iter()
                        .map(|(k, v)| (k.clone(), Value::from(*v)))
                        .collect::<serde_json::Map<_, _>>(),
                )
                .to_string(),
            );
        }
        new
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durable_counts_survive_reload() {
        let dir = std::env::temp_dir();
        let path = dir.join("warden_budget_test.json");
        let _ = std::fs::remove_file(&path);

        let b = Budget::file(&path);
        assert_eq!(b.increment("write_file"), 1);
        assert_eq!(b.increment("write_file"), 2);
        assert_eq!(b.increment("send_email"), 1);
        drop(b);

        // A fresh proxy reloads the persisted counts (no reset-by-restart).
        let b2 = Budget::file(&path);
        let snap = b2.snapshot();
        assert_eq!(snap.get("write_file"), Some(&2));
        assert_eq!(snap.get("send_email"), Some(&1));
        assert_eq!(b2.increment("write_file"), 3);

        let _ = std::fs::remove_file(&path);
    }
}
