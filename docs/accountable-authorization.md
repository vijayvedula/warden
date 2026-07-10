# Accountable Authorization for Agent Actions

> Status: design. Targets the model where every agent action is traceable to a
> named, accountable human -- the posture regulators (e.g. MAS's guidance on
> agentic AI, the EU AI Act's human-oversight clauses) are converging on.
> Builds on Warden's existing MCP-proxy + policy + tamper-evident audit core.

## 1. Problem

Warden today authorizes a flat principal: `--agent prod-agent`, matched against
tool name + one arg condition -> allow / deny / require_approval, with per-run
budgets ([policy.rs](../src/policy.rs)). There is no notion of *who the agent
acts for*, no roles, no resource identity, no relationships.

The regulatory direction is not "what can the agent do" but **"which named human
is answerable for what this agent just did, and could they have authorized it."**
That changes what a *principal* is. This document specifies the change.

## 2. Core principles

1. **Accountability is a delegation chain, not a name.** The principal is
   `human -> [service] -> agent -> run -> action`. If a call cannot resolve to a
   named accountable human, Warden **fails closed**.

2. **Authority is a narrowing, never an expansion.**
   `effective(agent) = grant(agent) & permissions(human) & context_guardrails`.
   An agent can never do more than the human it represents.

3. **Three authorization models, composed as layers -- not chosen between.**
   - **RBAC** -- what role is the principal in? (coarse capability classes)
   - **ABAC** -- do the attributes hold *right now*? (subject / resource / env)
   - **ReBAC** -- is there a relationship to *this specific* resource instance?
     (the only model that can scope an action to one object)

4. **Deny overrides.** Across all layers: `deny > require_approval > allow`.
   The evaluation order is itself an audit artifact.

5. **Unsigned / locally-derived inputs may only narrow, never widen.**
   See Sec 7.

6. **Identity is carried, not looked up.** Warden stays stateless on identity:
   it verifies a signed token and trusts its claims. All relationship/role
   resolution (OpenFGA, Zanzibar, JIT graph walks) is offloaded to whoever mints
   the token. This keeps Warden's interface clean and its hot path fast.

## 3. The session token -- Warden's identity boundary

A signed token, minted by the upstream identity stack, using **RFC 8693
(OAuth token exchange) delegation semantics**: `sub` is the party the token is
*about* (the accountable human), `act` is the *acting* party and nests to
express the full chain.

```jsonc
{
  // --- envelope Warden verifies ---
  "iss": "https://idp.internal",
  "aud": "warden:prod-tenant-eu",      // MUST equal this Warden instance, else reject
  "exp": 1750000300, "iat": 1750000000, "nbf": 1750000000,
  "jti": "tok_9f3a...",                // recorded in the audit chain

  // --- delegation chain (RFC 8693 `act`); nesting = accountability depth ---
  "sub": "human:alice@org",            // the ACCOUNTABLE party
  "act": {
    "sub": "service:reconciliation",
    "act": { "sub": "agent:recon-bot-7" }   // leaf = the actor on the wire
  },

  // --- RBAC ---
  "roles": ["ops.reconciler"],

  // --- ABAC: subject attributes (env attributes Warden computes itself) ---
  "attrs": { "clearance": "internal", "jurisdiction": "SG", "desk": "apac-ops" },

  // --- ReBAC: snapshot of relationship tuples scoping THIS token ---
  "rel": [
    { "relation": "manages", "resource": "account:123" },
    { "relation": "manages", "resource": "account:456" }
  ],

  // --- the agent's delegated grant (the grant(agent) term) ---
  "scope": ["read_ledger", "reconcile_*"]
}
```

**Verification (fail-closed on any miss):**

- signature against the issuer's key (JWKS or configured public key),
- `exp` / `nbf` window,
- `aud` equals this Warden instance/tenant,
- the leaf `act.sub` equals the connecting agent identity (wire identity must
  match the claim),
- a non-empty accountable `sub`.

`rel` is a **snapshot** the upstream resolved at mint time. Warden never queries
a relationship graph -- it checks set membership. Anyone wanting live ReBAC mints
shorter-lived tokens; that is their lever, not Warden's concern.

### Delegation granularity

Tokens are minted **per session or per action**, not one-per-agent. Short-lived,
narrowly-scoped tokens are the norm; the `act` chain captures accountability as
deep as the platform can express it.

## 4. Policy / rule model

Today's `Rule` is `{ tool, when, decision, max_per_run }`. It gains a subject
side and a resource side, and `when` generalizes from one tool arg to
**namespaced fields** (`arg:`, `subject:`, `env:`, `resource:`).

```toml
[[rules]]
tool = "transfer_funds"
require_role = "ops.reconciler"                                          # RBAC
require_relation = { relation = "manages", resource_arg = "account_id" } # ReBAC
when = [                                                                 # ABAC
  { field = "arg:amount",           op = "lt", value = 10000 },
  { field = "env:hour",             op = "lt", value = 18 },
  { field = "subject:jurisdiction", op = "eq", value = "SG" },
]
decision = "allow"

[[rules]]
tool = "transfer_funds"            # falls through here when amount >= 10000
decision = "require_approval"
reason = "high-value transfer requires human pre-authorization"
```

`require_relation` is the ReBAC primitive: *the resource named in arg
`account_id` must appear in the token's `rel` claim with relation `manages`.*
Enforcement is a set-membership check against the carried tuples -- no graph, no
latency, no state. An agent cannot touch `account:999` because that tuple is not
in its token.

## 5. Decision pipeline

```rust
fn authorize(token: &VerifiedToken, tool: &str, args: &Value, env: &Env, counts: &Counts)
    -> (Decision, Reason)
//  0. token verified; no accountable sub               => Deny (fail closed)
//  0b. principal/agent currently paused or revoked      => Deny  (see Sec 6)
//  1. tool ∉ token.scope                                => Deny  (agent's grant -- the narrowing)
//  2. require_role ∉ token.roles                        => Deny  (RBAC)
//  3. require_relation not satisfied by token.rel        => Deny  (ReBAC)
//  4. any `when` condition false                        => Deny  (ABAC: subject/env/arg)
//  5. budget exceeded                                   => Deny
//  6. rule.decision == require_approval                  => hold for the human
//  else                                                  => Allow
```

Combining rule across matched rules stays **deny > require_approval > allow**.
Step 1 enforces `effective = scope & role & rel & attrs`.

## 6. Revocation -- pause -> reload -> resume

Warden is single-node, file-backed, and loads policy at start
([main.rs](../src/main.rs)). Revocation is therefore modelled as an
**administrative config cycle**, not a live event stream:

```
admin -> control plane -> PAUSE agent -> update config -> RESUME agent
```

This deliberately separates two concerns that should not be bundled:

- **Config / policy change** wants this exactly: versioned, atomic,
  known-good-config-per-session. "What policy did this session run under?"
  answers with a config version.
- **Revocation** is human-driven incident response; a pause->reload cycle
  measured in seconds-to-minutes is acceptable because it is never on the hot
  path of normal operation.

### Two conditions that make it sound

1. **Pause is a Warden-side state, never an instruction to the agent.** The
   untrusted party must not enforce its own revocation. "Paused" means the proxy
   stops forwarding `tools/call` (holds or rejects) regardless of agent
   behaviour. This still requires a *minimal* control channel into Warden -- but
   only two verbs (`pause` / `resume`) plus config reload, deliverable as a CLI
   subcommand, a signal, or a watched control file. No broker, no event log.

2. **Drain semantics are explicit.** On pause, in-flight `tools/call`s and
   pending holds are *drained* (allowed to finish) or *aborted* -- choose and
   document per deployment. Note: per-run budget counts live in memory
   ([gateway.rs](../src/gateway.rs)) and reset on restart (desirable for
   revocation); approvals are file-backed and survive.

### What this model does NOT cover

**Selective, fine-grained revocation on a *shared* proxy** ("kill all of alice's
agents now, leave the other 50 sessions running"). Pause->reload is
stop-the-world at process/config granularity. This is a non-issue under a
**one-Warden-per-agent/session** topology (pausing one process *is* surgical),
which fits the current MVP. Revisit an event-driven revocation set only if/when
Warden becomes a multi-tenant shared proxy.

### The full revocation stack

```
Layer 1  Short token TTL                    passive revocation; bounds blast radius always
Layer 2  Admin: pause -> reload -> resume      coarse incident revocation; matches Warden today
Layer 3  Per-action hold (require_approval)  synchronous zero-lag stop for the high-risk tail
```

Layers 1 and 3 absorb the "can't wait for a restart" and "stop *this exact*
action now" cases that Layer 2 is slowest at.

## 7. The environment-attribute boundary

`env:` attributes (`env:hour`, request rate, source IP) are computed by Warden
at evaluation time. They are **outside the issuer's signature.** Therefore:

> **An unsigned, locally-derived input may only ever *narrow* authority -- never
> widen it.**

`env` conditions may push a decision toward `deny` or `require_approval`, but no
`env` value may be the thing that *grants* a call the signed token would not
otherwise allow. The worst a spoofed or incorrect env reading can do is
over-restrict, which fails safe. The same rule applies to the pause/revocation
state: it can only deny, never grant.

## 8. Audit chain changes

Accountability must be **tamper-evident, not merely appended.** The new fields
fold into `row_hash`'s material ([audit.rs:139](../src/audit.rs#L139)) so the
"who was accountable" record cannot be rewritten without breaking the chain:

```rust
pub struct Entry {
    // ...existing...
    pub accountable: String,          // token.sub -- the human
    pub act_chain: Vec<String>,       // ["service:reconciliation", "agent:recon-bot-7"]
    pub token_jti: String,            // which delegation authorized this
    pub matched: GateTrace,           // role / relation / conditions that decided it
    pub approval_jti: Option<String>, // the per-action signed approval, if held
    // approver already exists
}
```

When `require_approval` is released, the release is a **signed assertion binding
approver identity + token `jti` + a hash of `{tool, args}`** -- making it
per-action and replay-proof. Pause/config-version transitions are likewise
recorded so it is provable *when* and *under what policy* each action ran.

## 9. Open items

- Exact wire location of the token (env var vs MCP `initialize` metadata vs
  per-request field) -- see platform integration doc.
- `GateTrace` shape: how much of the decision rationale to persist.
- Whether `un-revoke` (resume after pause) needs its own signed authorization.
