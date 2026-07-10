//! AuthZEN -- the OpenID Authorization API (PEP ↔ PDP interop).
//!
//! Warden exposes its policy engine as an AuthZEN Policy Decision Point at
//! `POST /access/v1/evaluation`. Any AuthZEN-speaking PEP (gateway, mesh,
//! another platform) can ask Warden for a decision over a standard JSON shape,
//! decoupling policy from the proxy. Fail-closed: a malformed request -> deny.

use crate::policy::{Decision, PolicyConfig, Subject};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::collections::HashMap;

#[derive(Debug, Default, Deserialize)]
struct Entity {
    #[serde(default, rename = "type")]
    _type: String,
    #[serde(default)]
    id: String,
    #[serde(default)]
    properties: Map<String, Value>,
}

#[derive(Debug, Deserialize)]
struct Action {
    name: String,
    #[serde(default)]
    properties: Map<String, Value>,
}

#[derive(Debug, Deserialize)]
struct Request {
    #[serde(default)]
    subject: Entity,
    action: Action,
    #[serde(default)]
    resource: Entity,
    #[serde(default)]
    context: Map<String, Value>,
}

fn strings(v: Option<&Value>) -> Vec<String> {
    v.and_then(|x| x.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|s| s.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

/// Evaluate an AuthZEN request against the policy; return the AuthZEN response
/// JSON (always -- never errors to the caller; bad input => deny).
pub fn evaluate(policy: &PolicyConfig, body: &[u8]) -> String {
    let req: Request = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(e) => return deny(format!("invalid AuthZEN request: {e}")),
    };

    let p = &req.subject.properties;
    let rel: Vec<(String, String)> = p
        .get("rel")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|t| {
                    Some((
                        t.get("relation")?.as_str()?.to_string(),
                        t.get("resource")?.as_str()?.to_string(),
                    ))
                })
                .collect()
        })
        .unwrap_or_default();
    let attrs = p
        .get("attrs")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_else(|| p.clone());

    // Resource attributes keyed by resource id, for `resource:` conditions.
    let mut resource_attrs = Map::new();
    if !req.resource.id.is_empty() {
        resource_attrs.insert(
            req.resource.id.clone(),
            Value::Object(req.resource.properties.clone()),
        );
    }

    // Scope-narrowing is a Warden-token concept; an AuthZEN subject expresses
    // authority via roles/rel/attrs, so default to unconstrained when absent.
    let mut scope = strings(p.get("scope"));
    if scope.is_empty() {
        scope.push("*".to_string());
    }
    let subject = Subject {
        authenticated: true,
        roles: strings(p.get("roles")),
        attrs,
        rel,
        scope,
        resource_attrs,
    };

    // Build args: action properties + the resource id under conventional names.
    let mut args = req.action.properties.clone();
    if !req.resource.id.is_empty() {
        args.insert("resource_id".into(), Value::from(req.resource.id.clone()));
        args.insert("id".into(), Value::from(req.resource.id.clone()));
        if !req.resource._type.is_empty() {
            args.insert(
                format!("{}_id", req.resource._type),
                Value::from(req.resource.id.clone()),
            );
        }
    }

    let res = policy.evaluate(
        &req.action.name,
        &Value::Object(args),
        &subject,
        &req.context,
        &HashMap::new(),
    );
    let allow = res.decision == Decision::Allow;
    json!({
        "decision": allow,
        "context": {
            "id": "warden",
            "reason_admin": { "en": res.reason },
            "warden": { "decision": res.decision.as_str(), "trace": res.trace }
        }
    })
    .to_string()
}

fn deny(reason: String) -> String {
    json!({ "decision": false, "context": { "reason_admin": { "en": reason } } }).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY: &str = r#"
        default = "deny"
        require_identity = true
        [[rules]]
        tool = "transfer"
        require_role = "ops"
        require_relation = { relation = "manages", resource_arg = "resource_id" }
        decision = "allow"
    "#;

    #[test]
    fn authzen_allow_and_deny() {
        let p = PolicyConfig::from_str(POLICY).unwrap();
        let ok = br#"{
          "subject": {"type":"user","id":"alice","properties":{
              "roles":["ops"], "rel":[{"relation":"manages","resource":"acct:1"}] }},
          "action": {"name":"transfer"},
          "resource": {"type":"acct","id":"acct:1"}
        }"#;
        let r = evaluate(&p, ok);
        assert!(r.contains("\"decision\":true"));

        // wrong resource (no relationship) -> deny
        let bad = br#"{
          "subject": {"type":"user","id":"alice","properties":{
              "roles":["ops"], "rel":[{"relation":"manages","resource":"acct:1"}] }},
          "action": {"name":"transfer"},
          "resource": {"type":"acct","id":"acct:999"}
        }"#;
        assert!(evaluate(&p, bad).contains("\"decision\":false"));

        // malformed -> deny
        assert!(evaluate(&p, b"{not json").contains("\"decision\":false"));
    }
}
