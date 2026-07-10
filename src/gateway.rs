//! The control-plane core: intercept `tools/call`, apply policy, hold for
//! approval when required, forward allowed calls, and record everything with
//! the accountability chain of the principal the agent acts for.
//!
//! Concurrency: the gateway uses interior mutability so it can be shared as an
//! `Arc<Gateway>` across worker threads (one per in-flight request). A call
//! held for approval blocks only its own worker -- the upstream lock is released
//! during the wait, so other calls keep flowing. Shared mutable state
//! (upstream, per-run counts, audit, policy, control) is individually locked.

use crate::approvals::{Approvals, Status};
use crate::audit::{Accountability, AuditLog};
use crate::budget::Budget;
use crate::control::{Control, ControlState};
use crate::identity::{self, VerifiedToken, VerifyOpts};
use crate::jsonrpc::{Request, Response};
use crate::mcp::{parse_tool_call, result_is_tool_error, tool_error_result};
use crate::obs::Obs;
use crate::policy::{Decision, PolicyConfig, Subject};
use crate::revocation::RevocationSet;
use crate::upstream::Upstream;
use crate::util::now_unix;
use serde_json::{Map, Value};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, RwLock};
use std::time::{Duration, Instant};

/// The principal an agent acts for, re-validated per action (see `ensure_fresh`).
#[derive(Clone)]
pub(crate) struct Principal {
    subject: Subject,
    accountable: String,
    act_chain: Vec<String>,
    token_jti: String,
    /// Token expiry (unix). `None` => no expiry to enforce.
    exp: Option<u64>,
    /// DPoP key thumbprint the token is bound to (RFC 9449), if sender-constrained.
    dpop_jkt: Option<String>,
}

impl Principal {
    fn unauthenticated(agent: &str) -> Self {
        Principal {
            subject: Subject::default(),
            accountable: "-".to_string(),
            act_chain: vec![agent.to_string()],
            token_jti: String::new(),
            exp: None,
            dpop_jkt: None,
        }
    }

    fn from_token(token: &VerifiedToken) -> Self {
        let c = &token.claims;
        Principal {
            subject: Subject {
                authenticated: true,
                roles: c.roles.clone(),
                attrs: c.attrs.clone(),
                rel: c.rel_pairs(),
                scope: c.scope.clone(),
                resource_attrs: c.resource_attrs.clone(),
            },
            accountable: c.sub.clone(),
            act_chain: c.act_chain(),
            token_jti: c.jti.clone(),
            exp: c.exp,
            dpop_jkt: c.cnf_jkt().map(|s| s.to_string()),
        }
    }
}

/// Where to re-read the token from when it expires mid-session.
struct TokenSource {
    path: String,
    opts: VerifyOpts,
}

pub struct Gateway {
    policy: RwLock<PolicyConfig>,
    /// Where to reload policy from on resume (pause -> reload -> resume).
    policy_path: Option<String>,
    audit: Mutex<AuditLog>,
    approvals: Approvals,
    upstream: Mutex<Box<dyn Upstream + Send>>,
    agent: String,
    // --- principal (re-validated per action) ---
    principal: RwLock<Principal>,
    token_source: Option<TokenSource>,
    // --- approver authentication (allowlist of signing keys, kid = approver) ---
    approver_keys: Option<jsonwebtoken::jwk::JwkSet>,
    // --- event-driven revocation (negative authority) ---
    revocations: Option<Mutex<RevocationSet>>,
    // --- admin control plane ---
    control: Option<Control>,
    last_state: Mutex<ControlState>,
    counts: Budget,
    obs: Obs,
    /// Optional OCSF event sink (SIEM-ready), file path.
    ocsf: Option<String>,
    /// Optional Txn-Token signing key (PEM) -- mint call-context tokens on allow.
    txn_key: Option<Vec<u8>>,
    /// Optional Txn-Token verification key (PEM) -- verify inbound A2A tokens.
    txn_verify_key: Option<Vec<u8>>,
    /// High-assurance sinks: evidence must be acked before the action executes.
    blocking_sinks: Vec<crate::sink::Sink>,
    /// Optional bearer token required on the HTTP surface (gateway mode).
    http_auth: Option<String>,
    /// PII/secret redactor applied to recorded & exported data (not to the
    /// forwarded call, which keeps real args).
    redactor: crate::redact::Redactor,
    // --- MCP handshake ---
    initialized: AtomicBool,
    require_handshake: bool,
    /// Per-request identity: when set, each HTTP `tools/call` may carry its own
    /// bearer delegation token, verified with these opts to a per-call principal.
    /// This is how a shared gateway attributes each call to its accountable human.
    request_verify: Option<VerifyOpts>,
    approval_timeout: Duration,
    poll_interval: Duration,
}

/// What happened, for narrating the demo.
pub struct Outcome {
    pub response: Response,
    pub decision: Decision,
    pub outcome: String,
    #[allow(dead_code)]
    pub reason: String,
}

impl Gateway {
    pub fn new(
        policy: PolicyConfig,
        audit: AuditLog,
        approvals: Approvals,
        agent: &str,
        upstream: Box<dyn Upstream + Send>,
        approval_timeout: Duration,
    ) -> Self {
        Gateway {
            policy: RwLock::new(policy),
            policy_path: None,
            audit: Mutex::new(audit),
            approvals,
            upstream: Mutex::new(upstream),
            agent: agent.to_string(),
            principal: RwLock::new(Principal::unauthenticated(agent)),
            token_source: None,
            approver_keys: None,
            revocations: None,
            control: None,
            last_state: Mutex::new(ControlState::Running),
            counts: Budget::memory(),
            obs: Obs::new(false),
            ocsf: None,
            txn_key: None,
            txn_verify_key: None,
            blocking_sinks: Vec::new(),
            http_auth: None,
            redactor: crate::redact::Redactor::disabled(),
            initialized: AtomicBool::new(false),
            require_handshake: false,
            request_verify: None,
            approval_timeout,
            poll_interval: Duration::from_millis(100),
        }
    }

    /// Bind the verified session token, and (optionally) the source to re-read
    /// it from when it expires mid-session. Call before serving.
    pub fn set_principal(&mut self, token: VerifiedToken, path: &str, opts: VerifyOpts) {
        *self.principal.write().unwrap() = Principal::from_token(&token);
        self.token_source = Some(TokenSource {
            path: path.to_string(),
            opts,
        });
    }

    /// Re-validate the token before an action. If it has expired, try to reload
    /// a refreshed token from disk; if that fails, the session is no longer
    /// authorized (fail closed). Returns Err(reason) when expired and
    /// unrefreshable.
    fn ensure_fresh(&self, now: u64) -> Result<(), String> {
        let (exp, leeway) = {
            let p = self.principal.read().unwrap();
            if !p.subject.authenticated {
                return Ok(()); // unauth handled by policy require_identity
            }
            let leeway = self
                .token_source
                .as_ref()
                .map(|s| s.opts.leeway)
                .unwrap_or(0);
            (p.exp, leeway)
        };
        let Some(exp) = exp else { return Ok(()) };
        if now < exp.saturating_add(leeway) {
            return Ok(()); // still fresh
        }
        // Expired: attempt a refresh from the token source.
        if let Some(src) = &self.token_source {
            let mut opts = src.opts.clone();
            opts.now = now;
            if let Ok(token) = identity::load_and_verify(&src.path, &opts) {
                *self.principal.write().unwrap() = Principal::from_token(&token);
                eprintln!("warden: token refreshed for {}", token.claims.sub);
                return Ok(());
            }
        }
        Err("token expired; session no longer authorized".to_string())
    }

    /// Use a durable (file-backed) budget so per-run caps survive restarts.
    pub fn set_budget(&mut self, budget: Budget) {
        self.counts = budget;
    }

    /// Require signed approvals: only approvals carrying a valid assertion from
    /// an allowlisted approver key are honored. Call before serving.
    pub fn set_approver_keys(&mut self, keys: jsonwebtoken::jwk::JwkSet) {
        self.approver_keys = Some(keys);
    }

    /// Subscribe to a signed revocation feed (negative authority).
    pub fn set_revocations(&mut self, set: RevocationSet) {
        self.revocations = Some(Mutex::new(set));
    }

    /// Set the policy source path (for SIGHUP / resume reloads).
    pub fn set_policy_path(&mut self, path: &str) {
        self.policy_path = Some(path.to_string());
    }

    /// Reload policy from disk if a SIGHUP requested it (checked per action).
    fn maybe_reload(&self) {
        if RELOAD_REQUESTED.swap(false, Ordering::SeqCst) {
            if let Some(path) = &self.policy_path {
                match PolicyConfig::from_file(path) {
                    Ok(p) => {
                        *self.policy.write().unwrap() = p;
                        eprintln!("warden: SIGHUP -- policy reloaded from {path}");
                    }
                    Err(e) => eprintln!("warden: SIGHUP reload failed: {e}"),
                }
            }
        }
    }

    /// Enable pause/resume + policy reload via a control file. Call before serving.
    pub fn set_control(&mut self, control: Control, policy_path: &str) {
        *self.last_state.get_mut().unwrap() = control.state();
        self.control = Some(control);
        self.policy_path = Some(policy_path.to_string());
    }

    fn snapshot(&self) -> Principal {
        self.principal.read().unwrap().clone()
    }

    fn blocked(&self, req: &Request, decision: Decision, outcome: &str, reason: String) -> Outcome {
        Outcome {
            response: Response::ok(
                req.id.clone(),
                tool_error_result(format!("BLOCKED by Warden: {reason}")),
            ),
            decision,
            outcome: outcome.to_string(),
            reason,
        }
    }

    /// Environment attributes Warden computes itself (outside the token's
    /// signature, so they may only narrow a decision -- see policy.rs).
    fn env(&self) -> Map<String, Value> {
        let mut env = Map::new();
        let hour = (now_unix() / 3600) % 24;
        env.insert("hour".to_string(), Value::from(hour));
        env
    }

    #[allow(clippy::too_many_arguments)]
    fn audit_append(
        &self,
        tool: &str,
        args: &Value,
        decision: &str,
        outcome: &str,
        reason: &str,
        approver: Option<&str>,
        acct: &Accountability,
    ) {
        // Record a redacted projection of the args (data-minimisation); the
        // forwarded call keeps the real args.
        let red = self.redactor.redact(args);
        self.audit.lock().unwrap().append(
            &self.agent,
            tool,
            &red,
            decision,
            outcome,
            reason,
            approver,
            acct,
        );
    }

    /// Consult the control file. On a paused->running transition, reload policy.
    fn check_paused(&self) -> bool {
        let Some(control) = &self.control else {
            return false;
        };
        let state = control.state();
        let mut last = self.last_state.lock().unwrap();
        if *last == ControlState::Paused && state == ControlState::Running {
            if let Some(path) = &self.policy_path {
                if let Ok(p) = PolicyConfig::from_file(path) {
                    *self.policy.write().unwrap() = p;
                    eprintln!("warden: resumed; policy reloaded from {path}");
                }
            }
        }
        *last = state;
        state == ControlState::Paused
    }

    /// Forward a notification to the upstream (no response expected).
    pub fn notify(&self, req: &Request) {
        self.upstream.lock().unwrap().notify(req);
    }

    /// Sign a final audit checkpoint (call on graceful drain).
    pub fn checkpoint_audit(&self) {
        self.audit.lock().unwrap().checkpoint();
    }

    /// The DPoP thumbprint the current token is bound to (RFC 9449), if any.
    /// When set, the HTTP transport must see a valid DPoP proof per request.
    pub fn required_dpop_jkt(&self) -> Option<String> {
        self.principal.read().unwrap().dpop_jkt.clone()
    }

    /// Handle one JSON-RPC request. Non-`tools/call` methods pass straight
    /// through to the upstream; the `initialize` handshake is tracked.
    pub fn handle_request(&self, req: &Request, bearer: Option<&str>) -> Response {
        if req.method == "initialize" {
            self.initialized.store(true, Ordering::SeqCst);
            return self.upstream.lock().unwrap().request(req);
        }
        if req.method != "tools/call" {
            return self.upstream.lock().unwrap().request(req);
        }
        // A tool call before the handshake is a protocol violation -- and a way
        // to skip session setup. Reject it when handshake enforcement is on.
        if self.require_handshake && !self.initialized.load(Ordering::SeqCst) {
            return Response::ok(
                req.id.clone(),
                tool_error_result("BLOCKED by Warden: call `initialize` before `tools/call`"),
            );
        }
        let Some((tool, args)) = parse_tool_call(&req.params) else {
            return self.upstream.lock().unwrap().request(req);
        };
        let req_principal = self.principal_from_bearer(bearer);
        self.handle_tool_call(req, &tool, &args, req_principal)
            .response
    }

    /// Verify a per-request bearer delegation token into a principal, when
    /// per-request identity is configured (`request_verify`). Returns `None`
    /// when not configured, when no token is presented, or when the token fails
    /// verification -- in which case the call is unauthenticated and the policy's
    /// `require_identity` fails it closed.
    fn principal_from_bearer(&self, bearer: Option<&str>) -> Option<Principal> {
        let base = self.request_verify.as_ref()?;
        let token = bearer?;
        // Verify against the current time (exp/nbf), not the gateway's start time.
        let mut opts = base.clone();
        opts.now = now_unix();
        match identity::verify_token_str(token, &opts) {
            Ok(vt) => Some(Principal::from_token(&vt)),
            Err(e) => {
                eprintln!("warden: per-request token rejected: {e}");
                None
            }
        }
    }

    /// Configure per-request bearer token verification (shared-gateway identity).
    pub fn set_request_verify(&mut self, opts: VerifyOpts) {
        self.request_verify = Some(opts);
    }

    /// Use structured JSON decision logging (operational telemetry).
    pub fn set_observability(&mut self, json: bool) {
        self.obs = Obs::new(json);
    }

    /// Emit each decision as an OCSF event to this sink (SIEM-ready).
    pub fn set_ocsf(&mut self, path: &str) {
        self.ocsf = Some(path.to_string());
    }

    /// Mint a Txn-Token on each allowed action (propagates call context to A2A).
    pub fn set_txn_key(&mut self, pem: Vec<u8>) {
        self.txn_key = Some(pem);
    }

    /// High-assurance sinks: the action holds until each acks (fail closed).
    pub fn set_blocking_sinks(&mut self, sinks: Vec<crate::sink::Sink>) {
        self.blocking_sinks = sinks;
    }

    /// Require this bearer token on the HTTP surface (gateway mode).
    pub fn set_http_auth(&mut self, token: &str) {
        self.http_auth = Some(token.to_string());
    }

    /// Redact PII/secrets from recorded & exported data (not from the forwarded
    /// call). Configure with regulation profiles (gdpr/pci/hipaa/...).
    pub fn set_redactor(&mut self, redactor: crate::redact::Redactor) {
        self.redactor = redactor;
    }

    /// The expected HTTP bearer token, if HTTP authN is enabled.
    pub fn http_auth(&self) -> Option<&str> {
        self.http_auth.as_deref()
    }

    /// Ship evidence to blocking sinks before an action executes. Returns
    /// Err(reason) if any required sink can't durably ack -- fail closed.
    fn ship_blocking(
        &self,
        tool: &str,
        args: &Value,
        decision: &str,
        acct: &Accountability,
    ) -> Result<(), String> {
        if self.blocking_sinks.is_empty() {
            return Ok(());
        }
        let red = self.redactor.redact(args);
        let resource = red
            .get("account_id")
            .or_else(|| red.get("resource_id"))
            .or_else(|| red.get("id"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let ev = crate::sink::SinkEvent {
            ts: now_unix(),
            tool: tool.to_string(),
            decision: decision.to_string(),
            outcome: "authorizing".to_string(),
            accountable: acct.accountable.clone(),
            agent: self.agent.clone(),
            act_chain: acct.act_chain.clone(),
            jti: acct.token_jti.clone(),
            resource,
        };
        for s in &self.blocking_sinks {
            if s.wants(&ev) {
                s.ship(&ev)
                    .map_err(|e| format!("high-assurance sink `{}` unavailable: {e}", s.name()))?;
            }
        }
        Ok(())
    }

    /// Verify (or require) an inbound Txn-Token from a previous A2A hop.
    /// `params._meta["warden.txn_token"]` is checked against `--txn-verify-key`.
    /// Returns the upstream act-chain on success; a present-but-invalid token
    /// fails closed. None => no inbound token (or no verify key configured).
    pub fn set_txn_verify_key(&mut self, pem: Vec<u8>) {
        self.txn_verify_key = Some(pem);
    }

    fn verify_inbound(&self, req: &Request) -> Result<Option<Vec<String>>, String> {
        let Some(tok) = req
            .params
            .pointer("/_meta/warden.txn_token")
            .and_then(|v| v.as_str())
        else {
            return Ok(None);
        };
        let Some(key) = &self.txn_verify_key else {
            eprintln!("warden: inbound txn-token present but no --txn-verify-key; ignoring");
            return Ok(None);
        };
        let ctx = crate::txntoken::verify(tok, key, now_unix(), 60)
            .map_err(|e| format!("invalid inbound transaction token: {e}"))?;
        Ok(Some(ctx.rctx.act_chain))
    }

    /// Mint a Txn-Token for an allowed action and inject it into the forwarded
    /// request's `params._meta` so the next hop / upstream receives the context.
    fn inject_txn(
        &self,
        req: &Request,
        tool: &str,
        args: &Value,
        acct: &Accountability,
    ) -> Request {
        let Some(key) = &self.txn_key else {
            return req.clone();
        };
        let txn = if acct.token_jti.is_empty() {
            "anon"
        } else {
            &acct.token_jti
        };
        // The propagated token carries a redacted resource (it leaves the box).
        let red = self.redactor.redact(args);
        let resource = red
            .get("account_id")
            .or_else(|| red.get("resource_id"))
            .or_else(|| red.get("id"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let token = match crate::txntoken::mint(
            key,
            "warden",
            txn,
            &acct.accountable,
            tool,
            resource,
            &acct.act_chain,
            now_unix(),
            60,
        ) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("warden txn: {e}");
                return req.clone();
            }
        };
        let mut r = req.clone();
        if let Some(params) = r.params.as_object_mut() {
            let meta = params
                .entry("_meta")
                .or_insert_with(|| Value::Object(Map::new()));
            if let Some(m) = meta.as_object_mut() {
                m.insert("warden.txn_token".to_string(), Value::from(token));
            }
        }
        r
    }

    /// Build an accountability record, overriding the act-chain with a verified
    /// inbound A2A chain (this agent appended) when one is present.
    fn acct_chain(
        &self,
        p: &Principal,
        inbound: &Option<Vec<String>>,
        matched: &str,
        approval: Option<String>,
    ) -> Accountability {
        let mut a = acct(p, matched, approval);
        if let Some(ic) = inbound {
            a.act_chain = ic.clone();
            a.act_chain.push(self.agent.clone());
        }
        a
    }

    /// Require an MCP `initialize` handshake before any `tools/call`.
    pub fn set_require_handshake(&mut self, require: bool) {
        self.require_handshake = require;
    }

    /// Write a metrics snapshot and return a one-line summary (call on drain).
    pub fn report_metrics(&self, path: Option<&str>) -> String {
        if let Some(p) = path {
            self.obs.write_metrics(p);
        }
        self.obs.summary_line()
    }

    /// Answer an AuthZEN evaluation request against the current policy (PDP).
    pub fn authzen_evaluate(&self, body: &[u8]) -> String {
        crate::authzen::evaluate(&self.policy.read().unwrap(), body)
    }

    /// Current metrics as a JSON document (for the HTTP `/metrics` endpoint).
    pub fn metrics_json(&self) -> String {
        let counts: serde_json::Map<String, Value> = self
            .obs
            .snapshot()
            .into_iter()
            .map(|(k, v)| (k, Value::from(v)))
            .collect();
        serde_json::json!({ "total": self.obs.total(), "counts": counts }).to_string()
    }

    pub(crate) fn handle_tool_call(
        &self,
        req: &Request,
        tool: &str,
        args: &Value,
        req_principal: Option<Principal>,
    ) -> Outcome {
        let start = Instant::now();
        // The principal for this call: the per-request delegation token if one was
        // verified, else the process/session principal. Held locally so concurrent
        // requests never cross-attribute.
        let per_request = req_principal.is_some();
        let p = req_principal.unwrap_or_else(|| self.snapshot());
        let out = self.dispatch(req, tool, args, &p, per_request);
        let elapsed = start.elapsed();
        self.obs.record(
            tool,
            out.decision.as_str(),
            &out.outcome,
            elapsed,
            &p.accountable,
            &p.token_jti,
        );
        if let Some(sink) = &self.ocsf {
            let ev = crate::ocsf::event(
                tool,
                out.decision.as_str(),
                &out.outcome,
                elapsed.as_millis(),
                &p.accountable,
                &self.agent,
                &p.act_chain,
                &p.token_jti,
                now_unix(),
            );
            crate::ocsf::append(sink, &ev);
        }
        out
    }

    fn dispatch(
        &self,
        req: &Request,
        tool: &str,
        args: &Value,
        p: &Principal,
        per_request: bool,
    ) -> Outcome {
        // Pick up a SIGHUP-requested policy reload before deciding.
        self.maybe_reload();
        // Admin pause is enforced here, at Warden -- never by trusting the agent.
        if self.check_paused() {
            let reason = "Warden paused by admin".to_string();
            let acct = acct(p, "paused", None);
            self.audit_append(tool, args, "deny", "paused", &reason, None, &acct);
            return self.blocked(req, Decision::Deny, "paused", reason);
        }

        // Event-driven revocation (negative authority): tail the feed and deny
        // if this token / agent / accountable human has been revoked.
        if let Some(rev) = &self.revocations {
            let mut set = rev.lock().unwrap();
            set.refresh();
            if let Some(why) = set.is_revoked(&p.token_jti, &self.agent, &p.accountable) {
                drop(set);
                let reason = format!("revoked: {why}");
                let acct = acct(p, "revoked", None);
                self.audit_append(tool, args, "deny", "blocked", &reason, None, &acct);
                return self.blocked(req, Decision::Deny, "revoked", reason);
            }
        }

        // Inbound A2A: verify a forwarded Txn-Token (fail closed if invalid).
        let inbound = match self.verify_inbound(req) {
            Ok(c) => c,
            Err(reason) => {
                let acct = acct(p, "txn_invalid", None);
                self.audit_append(tool, args, "deny", "blocked", &reason, None, &acct);
                return self.blocked(req, Decision::Deny, "txn_invalid", reason);
            }
        };

        // Per-action token freshness for the process/session principal: expired =>
        // refresh-or-deny (fail closed). A per-request bearer token was already
        // exp-verified during its verification, so this is skipped for it.
        if !per_request {
            let now = now_unix();
            if let Err(reason) = self.ensure_fresh(now) {
                let acct = acct(p, "expired", None);
                self.audit_append(tool, args, "deny", "blocked", &reason, None, &acct);
                return self.blocked(req, Decision::Deny, "expired", reason);
            }
        }

        let env = self.env();
        let res = {
            let counts = self.counts.snapshot();
            self.policy
                .read()
                .unwrap()
                .evaluate(tool, args, &p.subject, &env, &counts)
        };
        let (decision, reason, trace) = (res.decision, res.reason, res.trace);
        match decision {
            Decision::Allow => {
                let acct = self.acct_chain(p, &inbound, &trace, None);
                self.forward(req, tool, args, decision, &reason, None, acct)
            }
            Decision::Deny => {
                let acct = acct(p, &trace, None);
                self.audit_append(
                    tool,
                    args,
                    decision.as_str(),
                    "blocked",
                    &reason,
                    None,
                    &acct,
                );
                Outcome {
                    response: Response::ok(
                        req.id.clone(),
                        tool_error_result(format!("BLOCKED by Warden: {reason}")),
                    ),
                    decision,
                    outcome: "blocked".to_string(),
                    reason,
                }
            }
            Decision::RequireApproval => {
                let id = self
                    .approvals
                    .ensure_pending(&self.agent, tool, args, &reason);
                match self.wait_for_decision(&id) {
                    ResolvedStatus::Approved(approver, assertion) => {
                        // If signed approvals are required, the assertion must
                        // verify against an allowlisted approver key and be
                        // bound to THIS action -- else fail closed.
                        if let Some(keys) = &self.approver_keys {
                            let ok = assertion
                                .as_deref()
                                .and_then(|a| crate::approval_sig::verify(a, keys, &id).ok());
                            if ok.is_none() {
                                let r =
                                    "approval not signed by an allowlisted approver".to_string();
                                let acct = acct(p, "approval_unverified", Some(id.clone()));
                                self.audit_append(
                                    tool,
                                    args,
                                    "deny",
                                    "blocked",
                                    &r,
                                    Some(&approver),
                                    &acct,
                                );
                                return self.blocked(req, Decision::Deny, "approval_unverified", r);
                            }
                        }
                        let acct = self.acct_chain(p, &inbound, &trace, Some(id.clone()));
                        let mut out =
                            self.forward(req, tool, args, decision, &reason, Some(&approver), acct);
                        out.outcome = format!("approved by {approver}; executed");
                        out
                    }
                    ResolvedStatus::Denied(approver) => {
                        let acct = acct(p, &trace, Some(id.clone()));
                        self.audit_append(
                            tool,
                            args,
                            decision.as_str(),
                            "denied",
                            &reason,
                            Some(&approver),
                            &acct,
                        );
                        Outcome {
                            response: Response::ok(
                                req.id.clone(),
                                tool_error_result(format!(
                                    "DENIED by reviewer {approver}: {reason}"
                                )),
                            ),
                            decision,
                            outcome: format!("denied by {approver}"),
                            reason,
                        }
                    }
                    ResolvedStatus::TimedOut => {
                        let acct = acct(p, &trace, Some(id));
                        self.audit_append(
                            tool,
                            args,
                            decision.as_str(),
                            "timeout",
                            &reason,
                            None,
                            &acct,
                        );
                        Outcome {
                            response: Response::ok(
                                req.id.clone(),
                                tool_error_result("approval timed out; action not taken"),
                            ),
                            decision,
                            outcome: "timeout".to_string(),
                            reason,
                        }
                    }
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn forward(
        &self,
        req: &Request,
        tool: &str,
        args: &Value,
        decision: Decision,
        reason: &str,
        approver: Option<&str>,
        acct: Accountability,
    ) -> Outcome {
        // High-assurance: durably record the authorization before acting.
        if let Err(reason) = self.ship_blocking(tool, args, decision.as_str(), &acct) {
            self.audit_append(
                tool,
                args,
                "deny",
                "sink_unavailable",
                &reason,
                approver,
                &acct,
            );
            return self.blocked(req, Decision::Deny, "sink_unavailable", reason);
        }
        self.counts.increment(tool);
        // Mint + inject a Txn-Token (call context) for the next hop, then forward.
        let send = self.inject_txn(req, tool, args, &acct);
        // Hold the upstream lock only for the forwarded round-trip.
        let response = self.upstream.lock().unwrap().request(&send);
        let executed_ok = response.error.is_none()
            && response
                .result
                .as_ref()
                .map(|r| !result_is_tool_error(r))
                .unwrap_or(false);
        let outcome = if executed_ok {
            "executed"
        } else {
            "upstream_error"
        };
        self.audit_append(
            tool,
            args,
            decision.as_str(),
            outcome,
            reason,
            approver,
            &acct,
        );
        Outcome {
            response,
            decision,
            outcome: outcome.to_string(),
            reason: reason.to_string(),
        }
    }

    fn wait_for_decision(&self, id: &str) -> ResolvedStatus {
        let deadline = Instant::now() + self.approval_timeout;
        loop {
            if let Some(record) = self.approvals.get(id) {
                match record.status {
                    Status::Approved => {
                        return ResolvedStatus::Approved(
                            record.approver.unwrap_or_else(|| "unknown".to_string()),
                            record.assertion,
                        )
                    }
                    Status::Denied => {
                        return ResolvedStatus::Denied(
                            record.approver.unwrap_or_else(|| "unknown".to_string()),
                        )
                    }
                    Status::Pending => {}
                }
            }
            if Instant::now() >= deadline {
                return ResolvedStatus::TimedOut;
            }
            std::thread::sleep(self.poll_interval);
        }
    }
}

enum ResolvedStatus {
    Approved(String, Option<String>),
    Denied(String),
    TimedOut,
}

/// Set by the SIGHUP handler; consumed by the gateway to reload policy.
static RELOAD_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Request a policy reload (called from the SIGHUP handler -- atomic store only).
pub fn request_reload() {
    RELOAD_REQUESTED.store(true, Ordering::SeqCst);
}

/// Build an audit accountability record from a principal snapshot.
fn acct(p: &Principal, matched: &str, approval_jti: Option<String>) -> Accountability {
    Accountability {
        accountable: p.accountable.clone(),
        act_chain: p.act_chain.clone(),
        token_jti: p.token_jti.clone(),
        matched: matched.to_string(),
        approval_jti,
    }
}

#[cfg(test)]
mod request_identity_tests {
    use super::*;
    use crate::upstream::DemoUpstream;
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use serde_json::json;

    const EC_PRIV: &str = include_str!("../fixtures/test_ec_priv.pem");
    const AGENT: &str = "agent:demo-gateway";
    const AUD: &str = "warden:demo";

    // Mint an ES256 RFC-8693 delegation token (sub=human, leaf act=agent).
    fn mint(sub: &str, agent_leaf: &str, aud: &str, exp: u64) -> String {
        let claims = json!({
            "iss": "example-idp", "aud": aud, "exp": exp, "jti": "tok_test",
            "sub": sub,
            "act": { "sub": agent_leaf },
            "scope": ["read_file"],
        });
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some("k1".to_string());
        let key = EncodingKey::from_ec_pem(EC_PRIV.as_bytes()).unwrap();
        encode(&header, &claims, &key).unwrap()
    }

    fn gateway_require_identity() -> Gateway {
        let policy =
            PolicyConfig::from_str("default = \"allow\"\nrequire_identity = true\n").unwrap();
        let tmp = std::env::temp_dir();
        let pid = std::process::id();
        let audit = AuditLog::new(tmp.join(format!("wt_audit_{pid}.jsonl")));
        let approvals = Approvals::new(tmp.join(format!("wt_appr_{pid}.json")));
        let mut g = Gateway::new(
            policy,
            audit,
            approvals,
            AGENT,
            Box::new(DemoUpstream::new()),
            Duration::from_secs(1),
        );
        g.set_request_verify(VerifyOpts {
            agent: AGENT.to_string(),
            now: now_unix(),
            expected_aud: Some(AUD.to_string()),
            expected_iss: None,
            leeway: 60,
            jwks_path: None,
            jwks_url: None,
            pem_path: Some("fixtures/test_ec_pub.pem".to_string()),
            dev_key: None,
            require_at_jwt: false,
        });
        g
    }

    fn read_file_call() -> Request {
        serde_json::from_value(json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": "read_file", "arguments": { "path": "/x" } }
        }))
        .unwrap()
    }

    fn blocked(resp: &Response) -> bool {
        serde_json::to_string(resp)
            .unwrap()
            .contains("BLOCKED by Warden")
    }

    #[test]
    fn valid_bearer_token_is_allowed() {
        let g = gateway_require_identity();
        let jwt = mint("human:alice@org", AGENT, AUD, now_unix() + 300);
        let resp = g.handle_request(&read_file_call(), Some(&jwt));
        assert!(!blocked(&resp), "valid delegation token should be allowed");
    }

    #[test]
    fn missing_token_fails_closed() {
        let g = gateway_require_identity();
        let resp = g.handle_request(&read_file_call(), None);
        assert!(
            blocked(&resp),
            "require_identity must deny an unauthenticated call"
        );
    }

    #[test]
    fn wrong_audience_fails_closed() {
        let g = gateway_require_identity();
        let jwt = mint(
            "human:alice@org",
            AGENT,
            "warden:someone-else",
            now_unix() + 300,
        );
        let resp = g.handle_request(&read_file_call(), Some(&jwt));
        assert!(blocked(&resp), "aud mismatch must deny");
    }

    #[test]
    fn expired_token_fails_closed() {
        let g = gateway_require_identity();
        let jwt = mint("human:alice@org", AGENT, AUD, now_unix() - 120); // past the 60s leeway
        let resp = g.handle_request(&read_file_call(), Some(&jwt));
        assert!(blocked(&resp), "expired token must deny");
    }
}
