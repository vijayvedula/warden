//! Event-driven revocation: the negative-authority plane (design Sec 6, Layer 2).
//!
//! Positive authority is carried in signed tokens (stateless). Revocation is
//! distributed as **signed, append-only events** on a feed that every proxy
//! tails (polls incrementally) and applies as an in-memory revocation set,
//! checked inline before each action. Revoke by `jti` (one token), `agent`
//! (all of an agent's sessions), or `human` (an accountable party's whole
//! authority). Events are ES256 JWTs signed by an admin key, so a compromised
//! feed file can't inject spurious revokes/un-revokes. The set only ever denies
//! -- never grants -- so a stale or unreachable feed fails safe.
//!
//! Multi-node: instances tail the same feed (shared storage / replicated file);
//! each applies events independently. The feed is the ordered log; polling is
//! the subscription.

use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::OpenOptions;
use std::io::Write;

#[derive(Debug, Serialize, Deserialize)]
struct Event {
    /// "jti" | "agent" | "human"
    kind: String,
    /// The revoked subject (the jti / agent id / human id).
    sub: String,
    ts: u64,
}

/// Sign a revocation event (ES256).
pub fn sign(key_pem: &[u8], kind: &str, subject: &str, ts: u64) -> Result<String, String> {
    let key = EncodingKey::from_ec_pem(key_pem).map_err(|e| format!("bad revoke key: {e}"))?;
    let ev = Event {
        kind: kind.to_string(),
        sub: subject.to_string(),
        ts,
    };
    encode(&Header::new(Algorithm::ES256), &ev, &key).map_err(|e| format!("sign revoke: {e}"))
}

/// Append a signed revocation event to the feed.
pub fn append(
    feed: &str,
    key_pem: &[u8],
    kind: &str,
    subject: &str,
    ts: u64,
) -> Result<(), String> {
    let jwt = sign(key_pem, kind, subject, ts)?;
    if let Some(parent) = std::path::Path::new(feed).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(feed)
        .map_err(|e| format!("open feed: {e}"))?;
    writeln!(file, "{jwt}").map_err(|e| format!("write feed: {e}"))
}

/// An in-memory revocation set, refreshed by tailing the signed feed.
pub struct RevocationSet {
    feed: String,
    key: DecodingKey,
    applied: usize,
    jtis: HashSet<String>,
    agents: HashSet<String>,
    humans: HashSet<String>,
}

impl RevocationSet {
    pub fn load(feed: &str, pub_pem: &[u8]) -> Result<Self, String> {
        let key =
            DecodingKey::from_ec_pem(pub_pem).map_err(|e| format!("bad revoke pubkey: {e}"))?;
        let mut set = RevocationSet {
            feed: feed.to_string(),
            key,
            applied: 0,
            jtis: HashSet::new(),
            agents: HashSet::new(),
            humans: HashSet::new(),
        };
        set.refresh();
        Ok(set)
    }

    /// Tail the feed: verify and apply any events appended since last refresh.
    /// Accepts Warden-native `{kind, sub}` events and standard CAEP Security
    /// Event Tokens (RFC 8417) carrying an `events` map.
    pub fn refresh(&mut self) {
        let Ok(text) = std::fs::read_to_string(&self.feed) else {
            return;
        };
        let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
        if lines.len() <= self.applied {
            return;
        }
        let mut validation = Validation::new(Algorithm::ES256);
        validation.required_spec_claims.clear();
        validation.validate_exp = false;
        validation.validate_aud = false;
        for line in &lines[self.applied..] {
            match decode::<serde_json::Value>(line, &self.key, &validation) {
                Ok(data) => self.apply_claims(&data.claims),
                Err(e) => eprintln!("warden revocation: rejected unsigned/invalid event: {e}"),
            }
        }
        self.applied = lines.len();
    }

    fn insert(&mut self, kind: &str, sub: String) {
        match kind {
            "jti" => self.jtis.insert(sub),
            "agent" => self.agents.insert(sub),
            "human" => self.humans.insert(sub),
            other => {
                eprintln!("warden revocation: unknown kind `{other}`");
                false
            }
        };
    }

    fn apply_claims(&mut self, claims: &serde_json::Value) {
        // CAEP Security Event Token: { "events": { "<type-uri>": { ... } } }
        if let Some(events) = claims.get("events").and_then(|v| v.as_object()) {
            for (uri, payload) in events {
                // Default Warden kind by CAEP event type; a `warden_kind` hint
                // on the subject overrides it.
                let default_kind = if uri.contains("session-revoked") {
                    "agent"
                } else if uri.contains("credential-change") {
                    "human"
                } else {
                    "jti" // token-claims-change & others
                };
                let subj = payload.get("subject").unwrap_or(payload);
                let kind = subj
                    .get("warden_kind")
                    .and_then(|v| v.as_str())
                    .unwrap_or(default_kind);
                if let Some(id) = subj
                    .get("id")
                    .or_else(|| claims.pointer("/sub_id/id"))
                    .and_then(|v| v.as_str())
                {
                    self.insert(kind, id.to_string());
                }
            }
            return;
        }
        // Warden-native event: { "kind": "...", "sub": "..." }
        if let (Some(kind), Some(sub)) = (
            claims.get("kind").and_then(|v| v.as_str()),
            claims.get("sub").and_then(|v| v.as_str()),
        ) {
            self.insert(kind, sub.to_string());
        }
    }

    /// Returns a reason if any of the principal's identifiers is revoked.
    pub fn is_revoked(&self, jti: &str, agent: &str, human: &str) -> Option<String> {
        if !jti.is_empty() && self.jtis.contains(jti) {
            return Some(format!("token {jti} revoked"));
        }
        if self.agents.contains(agent) {
            return Some(format!("agent {agent} revoked"));
        }
        if !human.is_empty() && self.humans.contains(human) {
            return Some(format!("accountable {human} revoked"));
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRIV: &str = include_str!("../fixtures/test_ec_priv.pem");
    const PUB: &str = include_str!("../fixtures/test_ec_pub.pem");

    #[test]
    fn signed_events_tail_and_apply() {
        let dir = std::env::temp_dir();
        let feed = dir.join("warden_revfeed_test.jsonl");
        let _ = std::fs::remove_file(&feed);
        let f = feed.to_string_lossy().to_string();

        let mut set = RevocationSet::load(&f, PUB.as_bytes()).unwrap();
        assert!(set.is_revoked("tok1", "agent:a", "human:x").is_none());

        // Admin revokes a jti; proxy tails and applies it live.
        append(&f, PRIV.as_bytes(), "jti", "tok1", 100).unwrap();
        set.refresh();
        assert!(set.is_revoked("tok1", "agent:a", "human:x").is_some());
        assert!(set.is_revoked("tok2", "agent:a", "human:x").is_none());

        // Revoke a human (cuts all their agents).
        append(&f, PRIV.as_bytes(), "human", "human:x", 200).unwrap();
        set.refresh();
        assert!(set.is_revoked("tok2", "agent:b", "human:x").is_some());

        let _ = std::fs::remove_file(&feed);
    }

    #[test]
    fn caep_set_event_applies() {
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        let dir = std::env::temp_dir();
        let feed = dir.join("warden_revfeed_caep.jsonl");
        let _ = std::fs::remove_file(&feed);
        let f = feed.to_string_lossy().to_string();

        // A CAEP Security Event Token: session-revoked for an agent subject.
        let set = serde_json::json!({
            "iss": "https://idp", "iat": 100, "jti": "set1",
            "events": {
                "https://schemas.openid.net/secevent/caep/event-type/session-revoked": {
                    "subject": { "format": "opaque", "id": "agent:bot-7", "warden_kind": "agent" }
                }
            }
        });
        let key = EncodingKey::from_ec_pem(PRIV.as_bytes()).unwrap();
        let jwt = encode(&Header::new(Algorithm::ES256), &set, &key).unwrap();
        std::fs::write(&feed, format!("{jwt}\n")).unwrap();

        let set_obj = RevocationSet::load(&f, PUB.as_bytes()).unwrap();
        assert!(set_obj
            .is_revoked("tokX", "agent:bot-7", "human:y")
            .is_some());
        assert!(set_obj
            .is_revoked("tokX", "agent:other", "human:y")
            .is_none());
        let _ = std::fs::remove_file(&feed);
    }

    #[test]
    fn unsigned_event_is_rejected() {
        let dir = std::env::temp_dir();
        let feed = dir.join("warden_revfeed_bad.jsonl");
        let _ = std::fs::remove_file(&feed);
        let f = feed.to_string_lossy().to_string();
        // Write a non-JWT line -- must be ignored, not applied.
        std::fs::write(&feed, "not-a-signed-event\n").unwrap();
        let set = RevocationSet::load(&f, PUB.as_bytes()).unwrap();
        assert!(set.is_revoked("tok1", "agent:a", "human:x").is_none());
        let _ = std::fs::remove_file(&feed);
    }
}
