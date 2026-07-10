//! The human-approval queue. File-backed so a separate `warden approve` process
//! (or the simulated reviewer in the demo) can resolve a held action.

use crate::util::{canonical_json, now_unix, sha256_hex};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Pending,
    Approved,
    Denied,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    pub id: String,
    pub agent: String,
    pub tool: String,
    pub args: Value,
    pub reason: String,
    pub status: Status,
    pub approver: Option<String>,
    /// Signed per-action assertion (ES256 JWT) when the approval is signed.
    #[serde(default)]
    pub assertion: Option<String>,
    pub created_unix: u64,
    pub resolved_unix: Option<u64>,
}

/// Cloneable handle; clones share one file lock so concurrent writers in the
/// same process don't corrupt the store. The file is the source of truth, so
/// cross-process readers (the CLI) see updates too.
#[derive(Clone)]
pub struct Approvals {
    path: PathBuf,
    lock: Arc<Mutex<()>>,
}

impl Approvals {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Approvals {
            path: path.into(),
            lock: Arc::new(Mutex::new(())),
        }
    }

    pub fn fingerprint(agent: &str, tool: &str, args: &Value) -> String {
        let material = format!("{agent}|{tool}|{}", canonical_json(args));
        sha256_hex(&material)[..16].to_string()
    }

    fn load(&self) -> HashMap<String, Record> {
        std::fs::read_to_string(&self.path)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default()
    }

    fn save(&self, records: &HashMap<String, Record>) {
        if let Some(parent) = self.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(
            &self.path,
            serde_json::to_string_pretty(records).unwrap_or_default(),
        );
    }

    pub fn get(&self, id: &str) -> Option<Record> {
        let _guard = self.lock.lock().unwrap();
        self.load().get(id).cloned()
    }

    pub fn list_pending(&self) -> Vec<Record> {
        let _guard = self.lock.lock().unwrap();
        let mut pending: Vec<Record> = self
            .load()
            .into_values()
            .filter(|r| r.status == Status::Pending)
            .collect();
        pending.sort_by_key(|r| r.created_unix);
        pending
    }

    /// Create a pending record if one doesn't already exist for this action.
    pub fn ensure_pending(&self, agent: &str, tool: &str, args: &Value, reason: &str) -> String {
        let id = Self::fingerprint(agent, tool, args);
        let _guard = self.lock.lock().unwrap();
        let mut records = self.load();
        records.entry(id.clone()).or_insert_with(|| Record {
            id: id.clone(),
            agent: agent.to_string(),
            tool: tool.to_string(),
            args: args.clone(),
            reason: reason.to_string(),
            status: Status::Pending,
            approver: None,
            assertion: None,
            created_unix: now_unix(),
            resolved_unix: None,
        });
        self.save(&records);
        id
    }

    pub fn set_status(
        &self,
        id: &str,
        status: Status,
        approver: &str,
        assertion: Option<&str>,
    ) -> Result<(), String> {
        let _guard = self.lock.lock().unwrap();
        let mut records = self.load();
        let record = records
            .get_mut(id)
            .ok_or_else(|| format!("no approval {id}"))?;
        record.status = status;
        record.approver = Some(approver.to_string());
        record.assertion = assertion.map(|s| s.to_string());
        record.resolved_unix = Some(now_unix());
        self.save(&records);
        Ok(())
    }
}
