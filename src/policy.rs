//! The policy engine: decide allow / deny / require-approval for a tool call.
//!
//! Three authorization models composed as layers (see
//! `docs/accountable-authorization.md`):
//!   - RBAC  -- `require_role`: the principal must hold a role.
//!   - ABAC  -- `when`: conditions over `arg:`, `subject:`, and `env:` fields.
//!   - ReBAC -- `require_relation`: the named resource must appear in the token's relationship tuples.
//!
//! Authority is a narrowing: an authenticated agent may only call tools inside
//! its delegated `scope`. Unsigned/local inputs (`env:`) can only ever *narrow*
//! a decision -- they gate allows, they never create them.

use serde::Deserialize;
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Deny,
    RequireApproval,
}

impl Decision {
    pub fn as_str(&self) -> &'static str {
        match self {
            Decision::Allow => "allow",
            Decision::Deny => "deny",
            Decision::RequireApproval => "require_approval",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    Gt,
    Lt,
    Eq,
    Contains,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum PolicyValue {
    Num(f64),
    Str(String),
}

/// A single ABAC condition. Either `field` (namespaced, e.g. `arg:amount`,
/// `subject:clearance`, `env:hour`) or the legacy bare `arg` form.
#[derive(Debug, Clone, Deserialize)]
pub struct Cond {
    #[serde(default)]
    pub field: Option<String>,
    #[serde(default)]
    pub arg: Option<String>,
    pub op: Op,
    pub value: PolicyValue,
}

impl Cond {
    /// Resolve to `(namespace, key)`. Legacy `arg = "x"` maps to `("arg", "x")`.
    fn target(&self) -> Option<(&str, &str)> {
        if let Some(f) = &self.field {
            let (ns, key) = f.split_once(':')?;
            Some((ns, key))
        } else {
            self.arg.as_deref().map(|a| ("arg", a))
        }
    }

    pub fn describe(&self) -> String {
        let target = self
            .field
            .clone()
            .or_else(|| self.arg.clone())
            .unwrap_or_else(|| "?".to_string());
        format!("{target} {:?}", self.op)
    }
}

/// A boolean match tree over conditions. `when` accepts a single condition,
/// an array (AND), or `{ all = [..] }` / `{ any = [..] }` / `{ not = .. }`.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum Match {
    Cond(Cond),
    All(Vec<Match>),
    AllObj { all: Vec<Match> },
    AnyObj { any: Vec<Match> },
    NotObj { not: Box<Match> },
}

impl Match {
    fn matches(
        &self,
        args: &Value,
        subject: &Subject,
        env: &Map<String, Value>,
        res: &Map<String, Value>,
    ) -> bool {
        match self {
            Match::Cond(c) => cond_matches(c, args, subject, env, res),
            Match::All(v) | Match::AllObj { all: v } => {
                v.iter().all(|m| m.matches(args, subject, env, res))
            }
            Match::AnyObj { any } => any.iter().any(|m| m.matches(args, subject, env, res)),
            Match::NotObj { not } => !not.matches(args, subject, env, res),
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Match::Cond(c) => c.describe(),
            Match::All(v) | Match::AllObj { all: v } => {
                format!(
                    "all[{}]",
                    v.iter()
                        .map(|m| m.describe())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            }
            Match::AnyObj { any } => {
                format!(
                    "any[{}]",
                    any.iter()
                        .map(|m| m.describe())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            }
            Match::NotObj { not } => format!("not({})", not.describe()),
        }
    }

    /// Collect the field namespaces referenced (for linting).
    fn namespaces(&self, out: &mut Vec<String>) {
        match self {
            Match::Cond(c) => {
                if let Some((ns, _)) = c.target() {
                    out.push(ns.to_string());
                }
            }
            Match::All(v) | Match::AllObj { all: v } | Match::AnyObj { any: v } => {
                v.iter().for_each(|m| m.namespaces(out))
            }
            Match::NotObj { not } => not.namespaces(out),
        }
    }
}

/// ReBAC requirement: the resource named in `resource_arg` must appear in the
/// principal's relationship tuples under `relation`.
#[derive(Debug, Clone, Deserialize)]
pub struct RelationReq {
    pub relation: String,
    pub resource_arg: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Rule {
    /// Tool name to match: exact, `*` (any), or a `prefix*` wildcard.
    pub tool: String,
    #[serde(default)]
    pub when: Option<Match>,
    /// RBAC: principal must hold this role.
    #[serde(default)]
    pub require_role: Option<String>,
    /// ReBAC: principal must have this relationship to the named resource.
    #[serde(default)]
    pub require_relation: Option<RelationReq>,
    pub decision: Decision,
    #[serde(default)]
    pub reason: Option<String>,
    /// Optional per-run budget; exceeding it denies the call.
    #[serde(default)]
    pub max_per_run: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PolicyConfig {
    pub default: Decision,
    /// When true, a call with no accountable identity is denied (fail closed).
    /// Off by default so the legacy/demo flow (no token) still runs.
    #[serde(default)]
    pub require_identity: bool,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

/// The principal making the call, as seen by the policy engine. Built from a
/// verified token; `authenticated = false` is the legacy/no-token path.
#[derive(Debug, Default, Clone)]
pub struct Subject {
    pub authenticated: bool,
    pub roles: Vec<String>,
    pub attrs: Map<String, Value>,
    /// Relationship tuples as `(relation, resource)`.
    pub rel: Vec<(String, String)>,
    pub scope: Vec<String>,
    /// Token-carried resource attributes: resource id -> {attr: value}. Used by
    /// `resource:` conditions; trusted because it rides in the signed token.
    pub resource_attrs: Map<String, Value>,
}

/// The result of evaluating one call.
#[derive(Debug, Clone)]
pub struct EvalResult {
    pub decision: Decision,
    pub reason: String,
    /// Compact trace of which gates decided it (for the audit record).
    pub trace: String,
}

/// Result of static policy linting.
pub struct LintReport {
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

impl PolicyConfig {
    #[allow(clippy::should_implement_trait)] // intentional inherent constructor, not FromStr
    pub fn from_str(text: &str) -> Result<Self, String> {
        toml::from_str(text).map_err(|e| format!("invalid policy: {e}"))
    }

    /// Static checks: unknown field namespaces, empty/zero settings,
    /// unreachable rules after a catch-all, and `resource:` without a relation.
    pub fn lint(&self) -> LintReport {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        let mut caught_all = false;

        for (i, rule) in self.rules.iter().enumerate() {
            let tag = format!("rule[{i}] tool=`{}`", rule.tool);
            if rule.tool.trim().is_empty() {
                errors.push(format!("{tag}: empty tool pattern"));
            }
            if caught_all {
                warnings.push(format!(
                    "{tag}: unreachable -- a prior catch-all rule always matches first"
                ));
            }
            if let Some(req) = &rule.require_relation {
                if req.resource_arg.trim().is_empty() {
                    errors.push(format!("{tag}: require_relation.resource_arg is empty"));
                }
            }
            if rule.max_per_run == Some(0) {
                warnings.push(format!("{tag}: max_per_run = 0 always denies"));
            }
            if let Some(when) = &rule.when {
                let mut ns = Vec::new();
                when.namespaces(&mut ns);
                for n in &ns {
                    if !matches!(n.as_str(), "arg" | "subject" | "env" | "resource") {
                        errors.push(format!("{tag}: unknown field namespace `{n}:`"));
                    }
                }
                if ns.iter().any(|n| n == "resource") && rule.require_relation.is_none() {
                    warnings.push(format!(
                        "{tag}: uses `resource:` but has no require_relation; resource attrs will be empty"
                    ));
                }
            }
            // A bare `*` rule with no gates makes everything after it dead.
            if rule.tool == "*"
                && rule.when.is_none()
                && rule.require_role.is_none()
                && rule.require_relation.is_none()
            {
                caught_all = true;
            }
        }
        LintReport { errors, warnings }
    }

    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("read policy: {e}"))?;
        Self::from_str(&text)
    }

    /// Evaluate a tool call against the layered pipeline.
    ///
    /// `env` carries Warden-computed environment attributes (e.g. `hour`).
    /// `counts` is per-run usage for budget rules.
    pub fn evaluate(
        &self,
        tool: &str,
        args: &Value,
        subject: &Subject,
        env: &Map<String, Value>,
        counts: &HashMap<String, u32>,
    ) -> EvalResult {
        // 0. No accountable identity, in identity-required mode => fail closed.
        if self.require_identity && !subject.authenticated {
            return EvalResult {
                decision: Decision::Deny,
                reason: "no accountable identity -- failing closed".to_string(),
                trace: "identity".to_string(),
            };
        }

        // 1. The narrowing: an authenticated agent may only act inside scope.
        if subject.authenticated && !scope_allows(tool, &subject.scope) {
            return EvalResult {
                decision: Decision::Deny,
                reason: format!("`{tool}` outside delegated scope"),
                trace: "scope".to_string(),
            };
        }

        for rule in &self.rules {
            if !tool_matches(&rule.tool, tool) {
                continue;
            }
            // `when` selects the applicable rule (fall through if it doesn't
            // match -- this preserves threshold rules like amount<X vs amount>=X).
            let res = resource_attrs_for(rule, args, subject);
            if !when_matches(&rule.when, args, subject, env, &res) {
                continue;
            }

            // Hard requirements on the selected rule.
            if let Some(role) = &rule.require_role {
                if !subject.authenticated || !subject.roles.iter().any(|r| r == role) {
                    return EvalResult {
                        decision: Decision::Deny,
                        reason: format!("missing required role `{role}`"),
                        trace: format!("rbac:{role}"),
                    };
                }
            }
            if let Some(req) = &rule.require_relation {
                match relation_satisfied(req, args, subject) {
                    Ok(resource) => {
                        if let Some(max) = rule.max_per_run {
                            if over_budget(tool, max, counts) {
                                return budget_denied(tool, max);
                            }
                        }
                        return decided(rule, format!("rebac:{}@{resource}", req.relation));
                    }
                    Err(why) => {
                        return EvalResult {
                            decision: Decision::Deny,
                            reason: why,
                            trace: format!("rebac:{}", req.relation),
                        }
                    }
                }
            }
            if let Some(max) = rule.max_per_run {
                if over_budget(tool, max, counts) {
                    return budget_denied(tool, max);
                }
            }
            return decided(rule, format!("rule:{}", rule.tool));
        }

        EvalResult {
            decision: self.default,
            reason: "no rule matched; default policy".to_string(),
            trace: "default".to_string(),
        }
    }
}

fn decided(rule: &Rule, trace: String) -> EvalResult {
    let reason = rule
        .reason
        .clone()
        .unwrap_or_else(|| format!("matched rule for {}", rule.tool));
    EvalResult {
        decision: rule.decision,
        reason,
        trace,
    }
}

fn over_budget(tool: &str, max: u32, counts: &HashMap<String, u32>) -> bool {
    counts.get(tool).copied().unwrap_or(0) >= max
}

fn budget_denied(tool: &str, max: u32) -> EvalResult {
    EvalResult {
        decision: Decision::Deny,
        reason: format!("budget exceeded: {tool} limited to {max} call(s) per run"),
        trace: "budget".to_string(),
    }
}

fn scope_allows(tool: &str, scope: &[String]) -> bool {
    scope.iter().any(|p| tool_matches(p, tool))
}

fn tool_matches(pattern: &str, tool: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return tool.starts_with(prefix);
    }
    pattern == tool
}

/// The `when` tree must hold for the rule. A missing field is a non-match.
fn when_matches(
    when: &Option<Match>,
    args: &Value,
    subject: &Subject,
    env: &Map<String, Value>,
    res: &Map<String, Value>,
) -> bool {
    match when {
        Some(m) => m.matches(args, subject, env, res),
        None => true,
    }
}

/// Resolve the resource-attribute map for a rule: the resource named in the
/// rule's `require_relation` arg, looked up in the token's `resource_attrs`.
fn resource_attrs_for(rule: &Rule, args: &Value, subject: &Subject) -> Map<String, Value> {
    if let Some(req) = &rule.require_relation {
        if let Some(rid) = args.get(&req.resource_arg).and_then(|v| v.as_str()) {
            if let Some(Value::Object(m)) = subject.resource_attrs.get(rid) {
                return m.clone();
            }
        }
    }
    Map::new()
}

fn cond_matches(
    cond: &Cond,
    args: &Value,
    subject: &Subject,
    env: &Map<String, Value>,
    res: &Map<String, Value>,
) -> bool {
    let Some((ns, key)) = cond.target() else {
        return false;
    };
    let resolved: Option<&Value> = match ns {
        "arg" => args.get(key),
        "subject" => subject.attrs.get(key),
        "env" => env.get(key),
        "resource" => res.get(key),
        _ => None,
    };
    let Some(value) = resolved else {
        return false;
    };
    match (&cond.op, &cond.value) {
        (Op::Gt, PolicyValue::Num(t)) => value.as_f64().is_some_and(|x| x > *t),
        (Op::Lt, PolicyValue::Num(t)) => value.as_f64().is_some_and(|x| x < *t),
        (Op::Eq, PolicyValue::Num(t)) => value
            .as_f64()
            .is_some_and(|x| (x - *t).abs() < f64::EPSILON),
        (Op::Eq, PolicyValue::Str(s)) => value.as_str().is_some_and(|x| x == s),
        (Op::Contains, PolicyValue::Str(s)) => value.as_str().is_some_and(|x| x.contains(s)),
        _ => false,
    }
}

/// ReBAC check: the resource named in `req.resource_arg` must appear in the
/// principal's tuples under `req.relation`. Returns the resource on success.
fn relation_satisfied(
    req: &RelationReq,
    args: &Value,
    subject: &Subject,
) -> Result<String, String> {
    if !subject.authenticated {
        return Err(format!(
            "relationship `{}` required but no identity present",
            req.relation
        ));
    }
    let resource = args
        .get(&req.resource_arg)
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("arg `{}` (resource id) missing", req.resource_arg))?
        .to_string();
    let has = subject
        .rel
        .iter()
        .any(|(rel, res)| rel == &req.relation && res == &resource);
    if has {
        Ok(resource)
    } else {
        Err(format!(
            "no `{}` relationship to `{resource}`",
            req.relation
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn empty_env() -> Map<String, Value> {
        Map::new()
    }
    fn no_counts() -> HashMap<String, u32> {
        HashMap::new()
    }

    fn authed() -> Subject {
        Subject {
            authenticated: true,
            roles: vec!["ops.reconciler".into()],
            attrs: serde_json::from_value(json!({"jurisdiction": "SG"})).unwrap(),
            rel: vec![("manages".into(), "account:123".into())],
            scope: vec!["wire_funds".into(), "read_*".into()],
            resource_attrs: serde_json::from_value(
                json!({"account:123": {"classification": "internal"}}),
            )
            .unwrap(),
        }
    }

    const POLICY: &str = r#"
        default = "allow"
        require_identity = true

        [[rules]]
        tool = "wire_funds"
        require_role = "ops.reconciler"
        require_relation = { relation = "manages", resource_arg = "account_id" }
        when = [ { field = "arg:amount", op = "lt", value = 10000 } ]
        decision = "allow"

        [[rules]]
        tool = "wire_funds"
        decision = "require_approval"
    "#;

    fn policy() -> PolicyConfig {
        PolicyConfig::from_str(POLICY).unwrap()
    }

    #[test]
    fn allow_when_role_relation_and_amount_ok() {
        let r = policy().evaluate(
            "wire_funds",
            &json!({"account_id": "account:123", "amount": 500}),
            &authed(),
            &empty_env(),
            &no_counts(),
        );
        assert_eq!(r.decision, Decision::Allow);
    }

    #[test]
    fn large_amount_falls_through_to_approval() {
        let r = policy().evaluate(
            "wire_funds",
            &json!({"account_id": "account:123", "amount": 50000}),
            &authed(),
            &empty_env(),
            &no_counts(),
        );
        assert_eq!(r.decision, Decision::RequireApproval);
    }

    #[test]
    fn wrong_account_denied_by_rebac() {
        let r = policy().evaluate(
            "wire_funds",
            &json!({"account_id": "account:999", "amount": 500}),
            &authed(),
            &empty_env(),
            &no_counts(),
        );
        assert_eq!(r.decision, Decision::Deny);
        assert!(r.trace.starts_with("rebac"));
    }

    #[test]
    fn out_of_scope_denied() {
        let mut s = authed();
        s.scope = vec!["read_*".into()]; // no wire_funds
        let r = policy().evaluate(
            "wire_funds",
            &json!({"account_id": "account:123", "amount": 500}),
            &s,
            &empty_env(),
            &no_counts(),
        );
        assert_eq!(r.decision, Decision::Deny);
        assert_eq!(r.trace, "scope");
    }

    #[test]
    fn no_identity_fails_closed() {
        let r = policy().evaluate(
            "wire_funds",
            &json!({"account_id": "account:123", "amount": 500}),
            &Subject::default(),
            &empty_env(),
            &no_counts(),
        );
        assert_eq!(r.decision, Decision::Deny);
        assert_eq!(r.trace, "identity");
    }

    #[test]
    fn or_not_combinators() {
        let p = PolicyConfig::from_str(
            r#"
            default = "deny"
            require_identity = true
            [[rules]]
            tool = "wire_funds"
            require_role = "ops.reconciler"
            require_relation = { relation = "manages", resource_arg = "account_id" }
            when = { any = [
                { field = "arg:amount", op = "lt", value = 100 },
                { field = "subject:jurisdiction", op = "eq", value = "SG" },
            ] }
            decision = "allow"
        "#,
        )
        .unwrap();
        // amount >= 100 but jurisdiction SG -> `any` still matches.
        let r = p.evaluate(
            "wire_funds",
            &json!({"account_id": "account:123", "amount": 5000}),
            &authed(),
            &Map::new(),
            &no_counts(),
        );
        assert_eq!(r.decision, Decision::Allow);
    }

    #[test]
    fn resource_attribute_condition() {
        let p = PolicyConfig::from_str(
            r#"
            default = "deny"
            require_identity = true
            [[rules]]
            tool = "wire_funds"
            require_relation = { relation = "manages", resource_arg = "account_id" }
            when = { field = "resource:classification", op = "eq", value = "internal" }
            decision = "allow"
        "#,
        )
        .unwrap();
        // account:123 has classification=internal in the token's resource_attrs.
        let r = p.evaluate(
            "wire_funds",
            &json!({"account_id": "account:123", "amount": 5}),
            &authed(),
            &Map::new(),
            &no_counts(),
        );
        assert_eq!(r.decision, Decision::Allow);
    }

    #[test]
    fn lint_flags_unreachable_and_unknown_namespace() {
        let p = PolicyConfig::from_str(
            r#"
            default = "allow"
            [[rules]]
            tool = "*"
            decision = "allow"
            [[rules]]
            tool = "wire_funds"
            when = { field = "bogus:x", op = "eq", value = "y" }
            decision = "deny"
        "#,
        )
        .unwrap();
        let report = p.lint();
        assert!(report.warnings.iter().any(|w| w.contains("unreachable")));
        assert!(report
            .errors
            .iter()
            .any(|e| e.contains("unknown field namespace")));
    }

    #[test]
    fn legacy_no_identity_mode_allows() {
        // require_identity defaults off -> unauthenticated demo flow still works.
        let p = PolicyConfig::from_str(
            r#"
            default = "allow"
            [[rules]]
            tool = "write_file"
            decision = "allow"
            max_per_run = 2
        "#,
        )
        .unwrap();
        let r = p.evaluate(
            "write_file",
            &json!({}),
            &Subject::default(),
            &empty_env(),
            &no_counts(),
        );
        assert_eq!(r.decision, Decision::Allow);
    }
}
