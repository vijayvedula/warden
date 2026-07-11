# What Warden is

Warden is a **policy enforcement and accountability layer for agent actions**.
It is not a model, an agent framework, or a tool server — it is the checkpoint
those things pass through when an agent tries to *do* something.

## The problem it solves

An autonomous agent decides, on its own, to call tools. Left ungoverned, a
prompt-injected or simply mistaken agent can delete a database, wire funds, or
exfiltrate data — and you may have no record of who was accountable or whether
the action was authorized. Access control at the *data* layer (IAM, Unity
Catalog, RBAC) governs what a *principal* can reach; it does not govern what an
*agent acting for that principal* actually does, call by call, with a human able
to intervene and a provable trail afterward.

Warden adds that **action layer**:

- **Bounded authority** — an agent may only call tools inside a delegated scope,
  under RBAC/ABAC/ReBAC rules, within per-run budgets.
- **Human-in-the-loop** — high-risk calls are *held* for synchronous approval.
- **Accountability** — every call is tied to a named human via a signed
  delegation token, and folded into a tamper-evident hash chain.

## What it is *not*

- **Not a jailbreak/prompt-injection filter.** Warden bounds *actions*, not the
  model's reasoning. A perfectly manipulated agent still cannot exceed its
  policy, scope, or budget, and cannot act without being recorded.
- **Not an IAM replacement.** Warden *consumes* your existing identity system
  (it verifies a token your IdP mints) and *complements* your data-layer access
  control with an action-layer brake and recorder.
- **Not tied to one cloud or framework.** The same Warden build runs everywhere;
  only a thin adapter differs per platform (see [The integration
  model](../integrating/model.md)).

## Where it runs

Warden speaks **MCP** (Model Context Protocol), the tool transport the major
agent platforms are converging on. It runs as:

- a **sidecar** — one Warden per agent session, on the stdio/HTTP MCP path
  (preferred), or
- a **shared gateway** — one Warden fronting many agents over HTTP.

See [Deployment patterns](../integrating/deployment.md).

## The four moving parts

| Part | Role |
|------|------|
| **[Proxy / decision pipeline](./how-it-works.md)** | Intercept every `tools/call`, decide, forward or block, record. |
| **[Identity token](./identity-token.md)** | A signed statement of *who the agent acts for* (RFC 8693 delegation). |
| **[Policy](./policy.md)** | Allow / deny / require-approval by tool, condition, role, relationship, and budget. |
| **[Audit chain](./audit.md)** | An append-only, hash-chained, optionally signed record of every decision. |

Read those four, and you understand Warden.
