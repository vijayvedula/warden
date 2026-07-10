//! Standards-based sinks -- where Warden's evidence & signals leave the box.
//!
//! A sink is `format x transport x filter x delivery`:
//!   - **format**: OCSF (SIEM/lake) or CAEP Security Event Token (RFC 8417 SET,
//!     so Warden is a Shared-Signals *transmitter*).
//!   - **transport**: append-file or signed HTTP webhook (RFC 8935 push).
//!   - **filter**: which events ship (all / deny / high-risk / revocation).
//!   - **delivery**: `fail-safe` (best-effort, tailing the audit WAL off the hot
//!     path) or `blocking` (high-assurance: the action holds until the evidence
//!     is durably acked -- no action without a recorded trail).
//!
//! The sink can only ever emit a *derived, projected* view; the canonical
//! tamper-evident chain stays local and authoritative.

use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde_json::json;
use std::fs::OpenOptions;
use std::io::Write;

/// The normalized fact a sink ships (a projection of one decision/audit row).
#[derive(Debug, Clone)]
pub struct SinkEvent {
    pub ts: u64,
    pub tool: String,
    pub decision: String,
    pub outcome: String,
    pub accountable: String,
    pub agent: String,
    pub act_chain: Vec<String>,
    pub jti: String,
    pub resource: String,
}

impl SinkEvent {
    /// Project an audit row into a sink event (used by the fail-safe forwarder).
    pub fn from_audit(e: &crate::audit::Entry) -> Self {
        let resource = e
            .args
            .get("account_id")
            .or_else(|| e.args.get("resource_id"))
            .or_else(|| e.args.get("id"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        SinkEvent {
            ts: e.ts_unix,
            tool: e.tool.clone(),
            decision: e.decision.clone(),
            outcome: e.outcome.clone(),
            accountable: e.accountable.clone(),
            agent: e.agent.clone(),
            act_chain: e.act_chain.clone(),
            jti: e.token_jti.clone(),
            resource,
        }
    }

    fn severity(&self) -> u8 {
        match self.decision.as_str() {
            "allow" => 1,
            "require_approval" => 2,
            _ => 3,
        }
    }
    fn is_revocation(&self) -> bool {
        self.outcome.contains("revoked")
    }
    fn high_risk(&self) -> bool {
        self.severity() >= 2
            || matches!(
                self.outcome.as_str(),
                "blocked" | "revoked" | "denied" | "timeout" | "paused"
            )
            || self.outcome.starts_with("denied")
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Filter {
    All,
    Deny,
    HighRisk,
    Revocation,
}

impl Filter {
    fn parse(s: &str) -> Filter {
        match s {
            "deny" => Filter::Deny,
            "high-risk" | "high_risk" => Filter::HighRisk,
            "revocation" => Filter::Revocation,
            _ => Filter::All,
        }
    }
    fn matches(&self, ev: &SinkEvent) -> bool {
        match self {
            Filter::All => true,
            Filter::Deny => ev.decision == "deny" || ev.outcome == "blocked",
            Filter::HighRisk => ev.high_risk(),
            Filter::Revocation => ev.is_revocation(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Delivery {
    FailSafe,
    Blocking,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Format {
    Ocsf,
    CaepSet,
}

/// A configured sink (parsed from `[[sink]]` in the config file).
pub struct Sink {
    name: String,
    format: Format,
    filter: Filter,
    delivery: Delivery,
    /// file path or webhook URL
    target: String,
    is_webhook: bool,
    /// ES256 signing key (required for CAEP SET).
    key: Option<EncodingKey>,
}

impl Sink {
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn delivery(&self) -> Delivery {
        self.delivery
    }
    pub fn wants(&self, ev: &SinkEvent) -> bool {
        self.filter.matches(ev)
    }

    /// Encode the event in this sink's format (signed SET when CAEP).
    fn encode(&self, ev: &SinkEvent) -> Result<(String, &'static str), String> {
        match self.format {
            Format::Ocsf => {
                let v = crate::ocsf::event(
                    &ev.tool,
                    &ev.decision,
                    &ev.outcome,
                    0,
                    &ev.accountable,
                    &ev.agent,
                    &ev.act_chain,
                    &ev.jti,
                    ev.ts,
                );
                Ok((v.to_string(), "application/json"))
            }
            Format::CaepSet => {
                let key = self
                    .key
                    .as_ref()
                    .ok_or("CAEP sink requires a signing key")?;
                Ok((sign_set(key, ev)?, "application/secevent+jwt"))
            }
        }
    }

    /// Ship one event; returns Ok on durable ack (file written / 2xx), else Err.
    pub fn ship(&self, ev: &SinkEvent) -> Result<(), String> {
        let (body, ctype) = self.encode(ev)?;
        if self.is_webhook {
            let resp = ureq::post(&self.target)
                .header("content-type", ctype)
                .send(body.as_bytes())
                .map_err(|e| format!("sink {} POST: {e}", self.name))?;
            if resp.status().is_success() {
                Ok(())
            } else {
                Err(format!("sink {} got HTTP {}", self.name, resp.status()))
            }
        } else {
            if let Some(parent) = std::path::Path::new(&self.target).parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let mut f = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.target)
                .map_err(|e| format!("sink {} open: {e}", self.name))?;
            writeln!(f, "{body}").map_err(|e| format!("sink {} write: {e}", self.name))
        }
    }
}

/// Sign a CAEP Security Event Token (RFC 8417) -- Warden as a Shared-Signals
/// transmitter. Revocations map to the CAEP `session-revoked` type; other
/// high-risk decisions use a Warden-namespaced event type.
fn sign_set(key: &EncodingKey, ev: &SinkEvent) -> Result<String, String> {
    let event_type = if ev.is_revocation() {
        "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
    } else {
        "https://warden.dev/secevent/event-type/action-decision"
    };
    let claims = json!({
        "iss": "https://warden.local",
        "iat": ev.ts,
        "jti": format!("set-{}-{}", ev.jti, ev.ts),
        "events": {
            event_type: {
                "subject": { "format": "opaque", "id": ev.accountable, "warden_kind": "human" },
                "agent": ev.agent,
                "act_chain": ev.act_chain,
                "tool": ev.tool,
                "decision": ev.decision,
                "outcome": ev.outcome,
                "resource": ev.resource
            }
        }
    });
    encode(&Header::new(Algorithm::ES256), &claims, key).map_err(|e| format!("sign SET: {e}"))
}

/// Parse `[[sink]]` entries from a TOML config file.
pub fn load_specs(config_path: &str) -> Result<Vec<Sink>, String> {
    let text = std::fs::read_to_string(config_path).map_err(|e| format!("read config: {e}"))?;
    let val: toml::Value = toml::from_str(&text).map_err(|e| format!("invalid config: {e}"))?;
    let mut sinks = Vec::new();
    let Some(arr) = val.get("sink").and_then(|v| v.as_array()) else {
        return Ok(sinks);
    };
    for s in arr {
        let get = |k: &str| s.get(k).and_then(|v| v.as_str()).unwrap_or("");
        let format = match get("format") {
            "caep" | "caep-set" | "set" => Format::CaepSet,
            _ => Format::Ocsf,
        };
        let transport = get("transport");
        let target = get("endpoint");
        if target.is_empty() {
            return Err("sink requires `endpoint` (file path or URL)".to_string());
        }
        let key = match get("key") {
            "" => None,
            kp => {
                let pem = std::fs::read(kp).map_err(|e| format!("read sink key: {e}"))?;
                Some(EncodingKey::from_ec_pem(&pem).map_err(|e| format!("sink key: {e}"))?)
            }
        };
        if format == Format::CaepSet && key.is_none() {
            return Err("CAEP sink requires a `key` (ES256 PEM)".to_string());
        }
        sinks.push(Sink {
            name: get("name").to_string(),
            format,
            filter: Filter::parse(get("filter")),
            delivery: if get("delivery") == "blocking" {
                Delivery::Blocking
            } else {
                Delivery::FailSafe
            },
            target: target.to_string(),
            is_webhook: transport == "webhook" || target.starts_with("http"),
            key,
        });
    }
    Ok(sinks)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const PRIV: &str = include_str!("../fixtures/test_ec_priv.pem");
    const PUB: &str = include_str!("../fixtures/test_ec_pub.pem");

    fn ev(decision: &str, outcome: &str) -> SinkEvent {
        SinkEvent {
            ts: 100,
            tool: "wire_funds".into(),
            decision: decision.into(),
            outcome: outcome.into(),
            accountable: "human:alice".into(),
            agent: "agent:bot".into(),
            act_chain: vec!["svc".into(), "agent:bot".into()],
            jti: "tok1".into(),
            resource: "acct:1".into(),
        }
    }

    #[test]
    fn filters_select_events() {
        assert!(Filter::All.matches(&ev("allow", "executed")));
        assert!(!Filter::Deny.matches(&ev("allow", "executed")));
        assert!(Filter::Deny.matches(&ev("deny", "blocked")));
        assert!(Filter::HighRisk.matches(&ev("require_approval", "approved")));
        assert!(Filter::Revocation.matches(&ev("deny", "revoked")));
        assert!(!Filter::Revocation.matches(&ev("deny", "blocked")));
    }

    #[test]
    fn caep_set_is_signed_and_verifiable() {
        use jsonwebtoken::{decode, DecodingKey, Validation};
        let key = EncodingKey::from_ec_pem(PRIV.as_bytes()).unwrap();
        let jwt = sign_set(&key, &ev("deny", "blocked")).unwrap();
        let mut v = Validation::new(Algorithm::ES256);
        v.required_spec_claims.clear();
        v.validate_exp = false;
        v.validate_aud = false;
        let data =
            decode::<Value>(&jwt, &DecodingKey::from_ec_pem(PUB.as_bytes()).unwrap(), &v).unwrap();
        // CAEP SET shape: a signed JWT carrying an `events` map.
        assert!(data.claims["events"].is_object());
        assert_eq!(data.claims["iss"], "https://warden.local");
    }
}
