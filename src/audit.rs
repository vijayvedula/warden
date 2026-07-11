//! Tamper-evident, hash-chained audit log -- the agent "black-box recorder".
//!
//! Each entry's `row_hash` covers its content plus the previous `row_hash`, so
//! altering any past entry breaks the chain from that point forward. The
//! accountability fields (who was answerable, under which delegation) are
//! folded into the hash too, so "who was accountable" cannot be rewritten
//! without breaking the chain -- the property the regulatory posture needs.

use crate::util::{canonical_json, now_unix, sha256_hex};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Who/what was accountable for an action, carried into the audit record.
#[derive(Debug, Clone, Default)]
pub struct Accountability {
    /// The accountable subject (token `sub`) -- a human. "-" if none.
    pub accountable: String,
    /// The delegation chain, outermost -> leaf actor.
    pub act_chain: Vec<String>,
    /// The token (`jti`) that authorized this action.
    pub token_jti: String,
    /// Compact trace of which policy gates decided it.
    pub matched: String,
    /// The per-action approval reference, when the call was held and released.
    pub approval_jti: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub seq: u64,
    pub ts_unix: u64,
    pub agent: String,
    pub tool: String,
    pub args: Value,
    pub decision: String,
    pub outcome: String,
    pub reason: String,
    pub approver: Option<String>,
    // --- accountability ---
    #[serde(default)]
    pub accountable: String,
    #[serde(default)]
    pub act_chain: Vec<String>,
    #[serde(default)]
    pub token_jti: String,
    #[serde(default)]
    pub matched: String,
    #[serde(default)]
    pub approval_jti: Option<String>,
    // --- chain ---
    pub prev_hash: String,
    pub row_hash: String,
}

impl Entry {
    /// A non-persisted placeholder returned when the log can't be written.
    fn placeholder() -> Entry {
        Entry {
            seq: 0,
            ts_unix: now_unix(),
            agent: String::new(),
            tool: String::new(),
            args: Value::Null,
            decision: String::new(),
            outcome: "audit_unavailable".to_string(),
            reason: String::new(),
            approver: None,
            accountable: String::new(),
            act_chain: Vec::new(),
            token_jti: String::new(),
            matched: String::new(),
            approval_jti: None,
            prev_hash: String::new(),
            row_hash: String::new(),
        }
    }
}

/// An open, exclusively-locked append handle plus the cached chain head, so
/// appends are O(1) (no full re-read) and a single writer is enforced.
struct Writer {
    file: File,
    last_seq: u64,
    last_hash: String,
}

/// Optional signed-checkpoint anchoring (see [`crate::anchor`]).
struct Anchor {
    signer: crate::anchor::Signer,
    path: String,
    interval: u64,
}

pub struct AuditLog {
    path: PathBuf,
    writer: Option<Writer>,
    anchor: Option<Anchor>,
}

impl AuditLog {
    pub fn new(path: impl AsRef<Path>) -> Self {
        AuditLog {
            path: path.as_ref().to_path_buf(),
            writer: None,
            anchor: None,
        }
    }

    /// Enable signed checkpoints: sign the head every `interval` appends (and
    /// on `checkpoint()`), writing to `anchor_path`.
    pub fn set_anchor(
        &mut self,
        key_pem: &[u8],
        anchor_path: &str,
        interval: u64,
    ) -> Result<(), String> {
        self.anchor = Some(Anchor {
            signer: crate::anchor::Signer::from_ec_pem(key_pem)?,
            path: anchor_path.to_string(),
            interval: interval.max(1),
        });
        Ok(())
    }

    /// Sign and persist a checkpoint of the current chain head.
    pub fn checkpoint(&mut self) {
        let (Some(anchor), Some(w)) = (&self.anchor, &self.writer) else {
            return;
        };
        if w.last_seq == 0 {
            return;
        }
        if let Err(e) =
            anchor
                .signer
                .append_checkpoint(&anchor.path, w.last_seq, &w.last_hash, now_unix())
        {
            eprintln!("warden anchor: {e}");
        }
    }

    pub fn read_all(&self) -> Vec<Entry> {
        let Ok(text) = std::fs::read_to_string(&self.path) else {
            return Vec::new();
        };
        text.lines()
            .filter(|l| !l.trim().is_empty())
            .filter_map(|l| serde_json::from_str::<Entry>(l).ok())
            .collect()
    }

    /// Lazily open the append handle, acquire an exclusive advisory lock (so a
    /// second process can't corrupt the chain), and seed the cached head from
    /// any existing entries.
    fn writer(&mut self) -> Result<&mut Writer, String> {
        if self.writer.is_none() {
            if let Some(parent) = self.path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let head = self.read_all();
            let last_seq = head.last().map(|e| e.seq).unwrap_or(0);
            let last_hash = head.last().map(|e| e.row_hash.clone()).unwrap_or_default();
            let file = OpenOptions::new()
                .create(true)
                .read(true)
                .append(true)
                .open(&self.path)
                .map_err(|e| format!("open audit log: {e}"))?;
            file.try_lock().map_err(|_| {
                format!(
                    "audit log {} is locked by another writer",
                    self.path.display()
                )
            })?;
            self.writer = Some(Writer {
                file,
                last_seq,
                last_hash,
            });
        }
        Ok(self.writer.as_mut().unwrap())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn append(
        &mut self,
        agent: &str,
        tool: &str,
        args: &Value,
        decision: &str,
        outcome: &str,
        reason: &str,
        approver: Option<&str>,
        acct: &Accountability,
    ) -> Entry {
        // Write the row under the (mutable) writer borrow, then drop it before
        // touching the anchor (which borrows self immutably).
        let entry = {
            let w = match self.writer() {
                Ok(w) => w,
                Err(e) => {
                    // Fail loud but don't crash the request path.
                    eprintln!("warden audit: {e}");
                    return Entry::placeholder();
                }
            };
            let seq = w.last_seq + 1;
            let prev_hash = w.last_hash.clone();
            let ts_unix = now_unix();
            let mut entry = Entry {
                seq,
                ts_unix,
                agent: agent.to_string(),
                tool: tool.to_string(),
                args: args.clone(),
                decision: decision.to_string(),
                outcome: outcome.to_string(),
                reason: reason.to_string(),
                approver: approver.map(|s| s.to_string()),
                accountable: acct.accountable.clone(),
                act_chain: acct.act_chain.clone(),
                token_jti: acct.token_jti.clone(),
                matched: acct.matched.clone(),
                approval_jti: acct.approval_jti.clone(),
                prev_hash: prev_hash.clone(),
                row_hash: String::new(),
            };
            entry.row_hash = row_hash(&entry, &prev_hash);
            let _ = writeln!(
                w.file,
                "{}",
                serde_json::to_string(&entry).unwrap_or_default()
            );
            let _ = w.file.flush();
            w.last_seq = seq;
            w.last_hash = entry.row_hash.clone();
            entry
        };
        // Sign a checkpoint of the head on the configured cadence.
        if let Some(anchor) = &self.anchor {
            if entry.seq % anchor.interval == 0 {
                if let Err(e) = anchor.signer.append_checkpoint(
                    &anchor.path,
                    entry.seq,
                    &entry.row_hash,
                    entry.ts_unix,
                ) {
                    eprintln!("warden anchor: {e}");
                }
            }
        }
        entry
    }

    /// Recompute the chain. Returns the verified entry count or the seq where
    /// it first breaks.
    pub fn verify(&self) -> Result<usize, String> {
        let entries = self.read_all();
        let mut prev = String::new();
        for entry in &entries {
            let expected = row_hash(entry, &prev);
            if entry.prev_hash != prev {
                return Err(format!(
                    "broken link at seq {}: prev_hash mismatch",
                    entry.seq
                ));
            }
            if entry.row_hash != expected {
                return Err(format!(
                    "tampered content at seq {}: row_hash mismatch",
                    entry.seq
                ));
            }
            prev = entry.row_hash.clone();
        }
        Ok(entries.len())
    }
}

fn row_hash(e: &Entry, prev_hash: &str) -> String {
    // Hash a canonical JSON object (sorted keys, JSON-escaped strings, nested
    // args preserved as structured JSON) -- NOT a raw `|`-delimited join. A join
    // is not injective: any field value containing the delimiter (`agent`,
    // `tool`, `reason`, `accountable`, the `>`-joined `act_chain`, or the fully
    // attacker-controlled `args`) could shift bytes across a field boundary so
    // two different rows produced the same hash, letting the log be rewritten
    // without breaking the chain. JSON encoding is unambiguous, closing that.
    let material = json!({
        "seq": e.seq,
        "ts": e.ts_unix,
        "agent": e.agent,
        "tool": e.tool,
        "args": e.args,
        "decision": e.decision,
        "outcome": e.outcome,
        "reason": e.reason,
        "approver": e.approver,
        "accountable": e.accountable,
        "act_chain": e.act_chain,
        "token_jti": e.token_jti,
        "matched": e.matched,
        "approval_jti": e.approval_jti,
        "prev": prev_hash,
    });
    sha256_hex(&canonical_json(&material))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(agent: &str, tool: &str) -> Entry {
        Entry {
            seq: 1,
            ts_unix: 0,
            agent: agent.to_string(),
            tool: tool.to_string(),
            args: json!({}),
            decision: "allow".to_string(),
            outcome: "executed".to_string(),
            reason: String::new(),
            approver: None,
            accountable: String::new(),
            act_chain: vec![],
            token_jti: String::new(),
            matched: String::new(),
            approval_jti: None,
            prev_hash: String::new(),
            row_hash: String::new(),
        }
    }

    #[test]
    fn row_hash_is_injective_across_field_boundaries() {
        // The old `|`-delimited join was not injective: a value containing the
        // delimiter could shift bytes across a field boundary so two DIFFERENT
        // rows produced the SAME hash. These two must now differ.
        let a = row_hash(&entry("bot", "wire|funds"), "prev");
        let b = row_hash(&entry("bot|wire", "funds"), "prev");
        assert_ne!(a, b, "delimiter-shifted fields must not collide");

        // Sanity: identical rows still hash identically (deterministic).
        let c = row_hash(&entry("bot", "wire|funds"), "prev");
        assert_eq!(a, c);
    }
}
