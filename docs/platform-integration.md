# Integrating Warden with Databricks, Google, and AWS agentic platforms

> Status: ideation. Companion to
> [accountable-authorization.md](accountable-authorization.md). Product details
> on these platforms move fast (knowledge cutoff Jan 2026); the *integration
> shape* -- token-as-interface -- is the stable part. Treat specific product
> names as "maps to," not "verified against the current API."

## 1. The integration thesis: the token is the interface

Warden's identity boundary is a single signed token (Sec 3 of the auth doc). That
is deliberately the *only* coupling point. Consequently, integrating any agentic
platform requires exactly two things:

1. **An issuer/verifier config** -- trust the platform's token issuer (its JWKS
   endpoint or public key, expected `aud`).
2. **A claims-mapping adapter** -- translate the platform's native identity
   concepts into Warden's canonical token claims (`sub`, `act`, `roles`,
   `attrs`, `rel`, `scope`).

Everything expensive -- JIT relationship resolution, role expansion, on-behalf-of
exchange -- stays on the platform side, where it already lives. Warden verifies
and evaluates. This is what keeps a single Warden build portable across clouds.

All three platforms are also converging on **MCP as the tool transport**, which
is exactly where Warden already sits. So the deployment story is uniform:
**Warden is the MCP proxy between the platform's agent runtime and its tool
servers**, and the platform's identity system mints the token.

## 2. Canonical claim mapping

| Warden claim | Databricks | Google | AWS |
|---|---|---|---|
| `sub` (accountable human) | UC user / on-behalf-of-user principal | IAM end-user principal (OIDC `sub`, domain-wide delegation subject) | Cognito/IdP user, or IAM user behind the role |
| `act` (delegation chain) | user -> service principal -> agent | user -> service account -> agent (workload identity) | user -> assumed role/STS session -> agent (AgentCore Identity) |
| `roles` (RBAC) | UC privileges / group membership | IAM roles / Google Groups | IAM role, Cognito groups |
| `attrs` (ABAC) | UC tags, workspace/catalog context | IAM condition attributes, org/folder context | **STS session tags** (native ABAC) |
| `rel` (ReBAC) | UC grants on specific securables (table/function/model) | IAM resource-level bindings; Zanzibar-style relations | resource-level IAM / resource tags scoped to the session |
| `scope` (agent grant) | tools registered for the agent (UC functions / MCP) | tools bound to the agent (function declarations / MCP) | AgentCore Gateway tool allow-list; session policy on AssumeRole |

The recurring pattern: each platform has (a) a token/credential issuer, (b) an
on-behalf-of / delegation mechanism, (c) an attribute facility, and increasingly
(d) MCP. Warden consumes all four through the one token.

## 3. Databricks (Mosaic AI Agent Framework / Unity Catalog)

**Where Warden sits:** as the MCP proxy in front of Databricks-hosted MCP
servers and Unity Catalog function tools, inside the agent serving environment
(Model Serving / Databricks Apps).

**What mints the token:** the agent runs as a **service principal** with
**on-behalf-of-user** authentication -- the human user who triggered the agent is
the accountable `sub`, the service principal is the middle `act`, the agent is
the leaf. Databricks issues the OBO credential; an adapter maps it to Warden's
token.

**What already exists vs. what Warden adds:** Unity Catalog governs the *data
layer* -- lineage, table/function grants, tags. That overlaps `rel`/`attrs` and
should be the *source* for them, not duplicated. Warden adds the **action layer**
on top: pre-authorization holds, per-run budgets, the cross-call accountability
chain, and the tamper-evident recorder UC lineage does not provide for tool
*invocations*. Map UC grants on a securable -> `rel` tuples so "agent may call
this UC function only on tables the user can read" is enforced at the action
boundary, replay-proof.

## 4. Google (Vertex AI Agent Engine / ADK / A2A)

**Where Warden sits:** MCP proxy between an ADK/Agent-Engine agent and its tool
servers; for inter-agent calls, alongside the **A2A** path.

**What mints the token:** Google IAM. The agent uses a **service account** (or
workload identity); the accountable human is carried via the OIDC `sub` /
domain-wide delegation subject. IAM **conditions** map cleanly to `attrs`
(ABAC), and IAM's emphasis on condition expressions is a natural fit for
Warden's `when` clauses.

**A2A angle:** the emerging Agent2Agent protocol has agent cards and an auth
story; the agent card's declared capabilities map to `scope`, and A2A's
delegation when one agent calls another extends the `act` chain by one hop.
Warden can be the enforcement point on the A2A tool/skill invocation, recording
each inter-agent delegation in the accountability chain.

**What Warden adds:** Google governs *access* via IAM; Warden adds the
human-pre-authorization hold for high-risk actions and the tamper-evident
per-action record tying each tool call back to a named IAM principal.

## 5. AWS (Bedrock AgentCore)

The closest existing analogue -- and the most important integration to position
against.

**Where Warden sits:** AWS **AgentCore Gateway** already turns APIs/Lambdas into
MCP tools, and **AgentCore Identity** handles agent identity, OAuth, and a token
vault. Warden inserts as the **policy + accountability layer on the MCP path**
between the agent runtime and the Gateway (or in front of the Gateway's MCP
endpoint).

**What mints the token:** AgentCore Identity / Cognito / IAM. The natural
mapping is strong here:

- **STS `AssumeRole` session = the delegation** -- the accountable human behind
  the role chain is `sub`, the session is the middle `act`.
- **STS session tags = native ABAC** -- they map directly onto `attrs` and
  Warden's `subject:` conditions.
- **Session policy on AssumeRole = the narrowing** -- maps to `scope`, the
  agent's delegated grant.

**What Warden adds over AgentCore alone:** AgentCore Gateway does tool exposure
and IAM does access control, but Warden contributes the **synchronous
human-pre-authorization hold**, **per-run budgets**, and the **tamper-evident,
hash-chained recorder** with the full delegation chain folded into the hash --
the "could the accountable human have known/authorized this, and can we prove
it" property that the regulatory posture demands. Position Warden as
complementary (a brake + black-box recorder on the action path), not a Gateway
replacement.

## 6. Common deployment patterns

- **Sidecar proxy** (preferred, matches the MVP): one Warden per agent
  runtime/session, on the MCP stdio/transport path. Makes the Sec 6 revocation
  model (pause->reload one process) surgical.
- **Shared gateway**: one Warden fronting many agents. Simpler to operate but
  forfeits surgical revocation (see the "shared proxy" caveat in the auth doc)
  and concentrates the trust boundary. Only adopt with the event-driven
  revocation set if fine-grained revocation is required.

## 7. What stays platform-agnostic vs. per-platform

| Platform-agnostic (build once) | Per-platform (thin adapter) |
|---|---|
| Token verification + decision pipeline | JWKS/issuer config, expected `aud` |
| Policy model (RBAC/ABAC/ReBAC rules) | Claims-mapping adapter (table Sec 2) |
| Pause/reload revocation, drain semantics | Where the token is sourced (OBO / STS / workload identity) |
| Tamper-evident audit chain | MCP transport wiring into the platform runtime |

The adapter is the only per-platform code, and it is pure data mapping -- no
policy logic. That is the payoff of treating the token as the sole interface.

## 8. Adapters & SDK

Because the token is the only interface (Sec 1), per-platform integration is pure
data mapping -- which is worth shipping as ready-made SDK packages so adoption is
seamless. Two design rules and a ship list.

### Two kinds of adapter (not one kind x4)

| Kind | Examples | Job | Where it runs |
|---|---|---|---|
| **Identity adapter** | Databricks, Google, AWS | Mint/shape the Warden token from the platform's native credential (OBO exchange, STS AssumeRole, workload identity) | Agent side; produces the signed token Warden verifies |
| **Orchestration adapter** | LangGraph, OpenAI Agents SDK, CrewAI, AutoGen, Google ADK runtime | Route the framework's tool calls through Warden's MCP proxy and attach the token | Agent side; **pairs with** an identity adapter -- frameworks have no token issuer of their own |

A LangGraph app has no `sub` to anchor to; it runs on top of a cloud or
self-hosted, so its orchestration adapter composes with an identity adapter.
The SDK is therefore *(orchestration shim per framework) x (identity adapter per
platform)*, composed -- not four interchangeable adapters.

### The no-forged-authority rule

From Warden's perspective an adapter is **untrusted client code** -- it runs on
the side Warden exists to police. Therefore:

> An adapter **orchestrates the platform's native token exchange; it never signs
> authority itself.** The trusted signer stays the platform issuer
> (Databricks / IAM / STS / AgentCore Identity); the adapter only shapes claims
> and asks the issuer to sign. Warden verifies against the issuer's JWKS.

An adapter that holds its own broad-scope signing key becomes a single
high-value secret and collapses the accountability model if the agent host is
compromised. Done correctly, the SDK is pure convenience with **no new trust
surface**.

### Ship list

1. **The canonical token spec, published** -- the real contract and the
   strategic asset. The proxy MUST always accept a raw conforming token with no
   SDK at all (the escape hatch; adoption is never coupled to client libraries).
2. **Token-builder + identity adapters** for the three clouds, **Python first**
   (covers Databricks, ADK, LangGraph, and boto at once), TS/JS second. Warden
   core stays Rust.
3. **Orchestration shims** -- LangGraph first (largest user base), then OpenAI
   Agents SDK / ADK / CrewAI.
4. **A conformance test kit** -- "does this adapter emit a valid, properly-signed
   Warden token?" -- so first-party *and* community adapters are verifiable, and
   the long tail can be offloaded to the community.

The moat is the token spec + proxy + audit chain; adapters are commodity glue.
Ship a few high-quality first-party adapters to seed adoption, conformance-test
them, and let the community write the rest. Prioritize by mapping cleanliness
(**AWS STS**, **Databricks OBO**) and adoption heat (**LangGraph**).

## 9. Open items

- Confirm each platform's current OBO/delegation primitive and whether it can
  carry custom claims (`rel`, `scope`) or needs a token-exchange shim that
  re-mints into Warden's RFC 8693 shape.
- Decide token transport into Warden (env var vs MCP `initialize` metadata vs
  per-request field) -- should be uniform across platforms.
- Validate the AgentCore positioning against the then-current product surface
  before any external claims.
