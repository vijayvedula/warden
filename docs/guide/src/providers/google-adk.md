# Google ADK / Vertex AI

This chapter shows how to put Warden in front of a
[Google Agent Development Kit (ADK)](https://google.github.io/adk-docs/) or
Vertex AI Agent Engine agent, so every `tools/call` is checked against policy
(allow / deny / require-approval), high-risk calls are held for a human, and
each executed call lands in a tamper-evident audit chain tied to a named IAM
principal.

Google IAM already governs *access*. Warden does not replace it — it adds the
two things IAM does not give you for tool *invocations*: a synchronous
**human pre-authorization hold** and a **tamper-evident per-action record**. IAM
mints the credential; Warden maps and enforces what IAM already asserts, and
never invents authority of its own.

The runnable version of everything here lives in
[`examples/google-adk`](https://github.com/vijayvedula/warden/tree/main/examples/google-adk).

## Overview

Warden is an MCP proxy. It sits on the stdio (or HTTP) path between the ADK /
Agent-Engine agent and its tool servers. The only integration change is that the
agent's MCP toolset launches `warden proxy …` instead of launching the tool
server directly; Warden then spawns the tool server as its own upstream
subprocess.

```
ADK / Agent-Engine agent --(MCP)--> warden proxy --(MCP)--> tool servers
        |                              |
        | A2A hops extend `act`        | verify identity / evaluate policy
        |                              | hold for approval / append to audit
        +------------------------------> each call tied to a named IAM principal
```

### The A2A angle

For inter-agent work, Google's emerging **Agent2Agent (A2A)** protocol has agent
cards (which declare an agent's capabilities) and its own auth story. Warden is
the enforcement point on the A2A tool/skill invocation:

- an agent card's declared capabilities become the granted `scope`;
- when one agent calls another, that hop **extends the `act` chain by one**, so
  the delegation from human → agent A → agent B is carried in the token and
  folded into the audit record;
- each inter-agent delegation is recorded in the accountability chain, so "which
  agent, acting for which human, invoked this skill" is provable after the fact.

See [The integration model](../integrating/model.md) for why the token is the
only coupling point, and
[docs/platform-integration.md §4](https://github.com/vijayvedula/warden/blob/main/docs/platform-integration.md)
for the Google / Vertex / A2A design notes.

## Identity mapping

Warden's identity boundary is a single signed
[delegation token](../concepts/identity-token.md) (RFC 8693): `sub` is the
accountable human, `act` is the nested acting chain whose **leaf** equals the
agent's wire identity, and the authorization claims (`roles`, `attrs`, `rel`,
`scope`) are trusted-because-signed. The Google adapter shapes those claims from
IAM; the platform issuer signs.

| Warden claim | Google source |
| --- | --- |
| `sub` — accountable human | OIDC `sub` / domain-wide-delegation subject |
| `act` — acting chain (leaf = agent) | service account (workload identity); **each A2A hop adds one more `act` entry** |
| `roles` (RBAC) | IAM role bindings (e.g. `roles/bigquery.dataViewer`) |
| `attrs` (ABAC) | IAM **conditions** (e.g. `resource.type == "bigquery"`) |
| `scope` (agent grant) | agent-card A2A capabilities |
| `rel` (ReBAC tuples) | resource-level IAM bindings (Zanzibar-style relations) |

IAM's emphasis on condition expressions is a natural fit for Warden's policy
`when` clauses, which read those conditions back out of `attrs`.

## Prerequisites

- **Build Warden** and put the `warden` binary on your `PATH` (or set
  `WARDEN_BIN` — the SDK resolves the binary in that order). See
  [Install & build](../getting-started/install.md).
- **Install the SDK** and the ADK wiring:

  ```sh
  pip install warden-sdk        # identity adapter + orchestration shim
  pip install google-adk        # ADK, for the MCP toolset
  pip install "warden-sdk[jwt]" # only needed for production JWT signing
  ```

- **A GCP project** with the agent running as a **service account** (or a
  workload-identity binding), plus the IAM role bindings, conditions, and
  resource-level bindings you want to project into the token.

## Step 1 — Mint a Warden token

Map the agent's Google workload-identity context into a Warden token with the
identity adapter. Its entry point is
`warden_sdk.adapters.google.from_workload_identity(context, *, agent, audience,
ttl_seconds=300)`, which returns a `TokenBuilder`.

```python
from warden_sdk.adapters import google

# In production this dict is assembled from the service account's IAM bindings
# and conditions plus the agent card's declared capabilities — not hand-written.
context = {
    "user": "alice@example.com",                                  # OIDC sub / DWD subject -> sub
    "service_account": "prod-agent@my-proj.iam.gserviceaccount.com",  # -> act hop
    "iam_roles": ["roles/bigquery.dataViewer"],                   # -> roles (RBAC)
    "iam_conditions": {"resource.type": "bigquery"},              # IAM condition -> attrs (ABAC)
    "a2a_capabilities": ["query_dataset"],                        # agent-card capabilities -> scope
    "resource_bindings": [                                        # resource-level IAM -> rel (ReBAC)
        {"relation": "dataViewer", "resource": "dataset:analytics"},
    ],
}

tok = google.from_workload_identity(
    context,
    agent="prod-agent",       # becomes the leaf `act` — must match the proxy's --agent
    audience="warden:google",
)
```

Context keys (exact): `user` is **required** (the human `sub`; missing it raises
`ValueError`). `service_account` → the middle `act` hop. `iam_roles` (list) →
`roles`. `iam_conditions` (dict) → `attrs`. `a2a_capabilities` (list) → `scope`.
`resource_bindings` (list of `{"relation", "resource"}`) → `rel` tuples.

### Local (dev envelope)

For offline runs, emit an unsigned/dev-signed envelope. Its signature verifies
under `--token-key`; it is a development convenience, **not** an enforcement
mode.

```python
import os
os.makedirs(".warden", exist_ok=True)
tok.write_dev_envelope(".warden/token.json", key="dev-secret")
```

Or run the example's minter directly:

```sh
python mint_token.py alice@example.com
```

### Production (real signed JWT)

In production, **do not** use the dev envelope. Have the platform issuer —
Google IAM or your IdP — sign a real JWT and have the proxy verify it against the
issuer's JWKS. The adapter only shapes claims; it asks the issuer to sign.

```python
from warden_sdk import JwtSigner

# The private key belongs in a KMS/HSM / Secret Manager; this is the local signer.
signer = JwtSigner.from_file("issuer.pem", "ES256", "k1")
jwt = tok.to_jwt(signer, at_jwt=True)   # RFC 9068 at+jwt so --require-at-jwt accepts it
```

Warden accepts **only asymmetric algorithms** (RS*/PS*/ES*/EdDSA), which blocks
the RS256→HS256 confusion downgrade.

> **The no-forged-authority rule.** From Warden's perspective the adapter is
> untrusted client code — it runs on the side Warden exists to police. An adapter
> *orchestrates the platform's token exchange; it never signs authority itself.*
> The trusted signer stays the platform issuer (IAM / your IdP); Warden verifies
> against the issuer's JWKS. An adapter holding its own broad-scope signing key
> would be a single high-value secret that collapses the accountability model.

### Verify the token

Confirm the token is well-formed and the `act` leaf matches the agent before you
wire anything up:

```sh
# dev envelope
warden token verify --token .warden/token.json \
    --agent prod-agent --aud warden:google --token-key dev-secret

# production JWT
warden token verify --token .warden/token.json \
    --agent prod-agent --aud warden:google --jwks path/to/jwks.json
```

## Step 2 — Route ADK tool calls through Warden

ADK consumes tools via an MCP toolset. Use the orchestration shim
`warden_sdk.orchestration.google_adk.warden_connection_params(cfg)` to build the
stdio parameters that launch `warden proxy` as that toolset's server. It takes a
[`ProxyConfig`](../integrating/sdk.md) and returns
`{"command": …, "args": [...]}`, ready to splat into ADK's
`StdioServerParameters`.

```python
from google.adk.tools.mcp_tool.mcp_toolset import MCPToolset, StdioServerParameters
from warden_sdk import ProxyConfig
from warden_sdk.orchestration import google_adk as wg

cfg = ProxyConfig(
    upstream="python3 tools_server.py",   # Warden spawns this as its MCP upstream
    agent="prod-agent",                   # must equal the token's leaf act
    policy="warden.policy.toml",
    token=".warden/token.json",
    audience="warden:google",
    audit=".warden/audit.jsonl",
    approvals=".warden/approvals.json",
)

params = wg.warden_connection_params(cfg)          # -> {"command": ..., "args": [...]}
toolset = MCPToolset(connection_params=StdioServerParameters(**params))
```

That `toolset` is the only Warden-aware line in the agent; the rest of your ADK
agent (models, instructions, other tools) is unchanged. Under the hood the shim
resolves the `warden` binary (`warden_bin` → `WARDEN_BIN` → `PATH`) and expands
to `warden proxy --upstream "python3 tools_server.py" --agent prod-agent
--policy … --token … --aud warden:google --audit … --approvals …`.

For a **production JWT** flow, drop `token`/`audience` for an issuer-verified
config and set `jwks_url`, `issuer`, and `audience` on the `ProxyConfig` (or run
the proxy by hand with `--jwks-url` / `--iss` / `--aud`).

## Step 3 — Write a policy

Policy is TOML: first matching rule wins, otherwise `default`. Setting
`require_identity = true` makes every action tie back to a named IAM principal —
no anonymous tool calls. This mirrors
[`examples/google-adk/warden.policy.toml`](https://github.com/vijayvedula/warden/tree/main/examples/google-adk).

```toml
# Warden policy for a Google ADK / Vertex AI Agent Engine agent.
default = "deny"
require_identity = true

# Reads are allowed for principals holding the BigQuery dataViewer IAM role.
# The role arrives as an RBAC claim mapped from the service account's IAM binding.
[[rules]]
tool = "read_*"
decision = "allow"
require_role = "roles/bigquery.dataViewer"

# Dataset queries are gated on a ReBAC relationship: the token must carry a
# `dataViewer` relation to the exact dataset named in the call's `dataset` arg
# (resource-level IAM binding -> rel tuple). No tuple, no query.
[[rules]]
tool = "query_dataset"
decision = "allow"
require_relation = { relation = "dataViewer", resource_arg = "dataset" }

# Optional ABAC tightening: only within the BigQuery resource type. The attr is
# mapped from an IAM condition (iam_conditions -> attrs).
[[rules]]
tool = "describe_dataset"
decision = "allow"
require_role = "roles/bigquery.dataViewer"
when = { field = "subject:resource.type", op = "eq", value = "bigquery" }

# Destructive operations are never allowed unattended, regardless of role.
[[rules]]
tool = "delete_*"
decision = "deny"
reason = "destructive: agents may not delete datasets or tables"
```

How each rule reads back the mapped claims:

- **`read_*` → `require_role`** consumes `roles`, i.e. the IAM role binding
  (`roles/bigquery.dataViewer`) projected in Step 1.
- **`query_dataset` → `require_relation`** consumes `rel`. The
  `{ relation, resource_arg }` form means: the token must carry a `dataViewer`
  relation whose resource **exactly equals** the value of the call's `dataset`
  argument. With the sample token that relation is to `dataset:analytics`, so a
  call with `dataset = "dataset:analytics"` passes and any other dataset is
  denied.
- **`describe_dataset` → `when`** reads `attrs["resource.type"]` (mapped from the
  IAM condition) via the `subject:` field prefix.
- **`delete_*` → `deny`** blocks destructive calls before they reach the tool.

To gate (rather than block) a high-risk call for a human, use
`decision = "require_approval"`; see the [Policy model](../concepts/policy.md)
and [Policy reference](../reference/policy.md).

## Step 4 — Run & verify

The ADK toolset launches Warden for you. To exercise the same proxy by hand
against the policy above:

```sh
warden proxy --upstream "python3 tools_server.py" --agent prod-agent \
    --policy warden.policy.toml --token .warden/token.json --aud warden:google \
    --audit .warden/audit.jsonl --approvals .warden/approvals.json
```

With this policy in place: reads pass for the `roles/bigquery.dataViewer` role;
`query_dataset` passes only when the token holds a `dataViewer` relation to the
exact dataset it targets; and any `delete_*` is denied before it reaches the
tool. A `require_approval` decision parks the call until a human runs
`warden approve <id>` / `warden deny <id>`.

Inspect the record. Every executed or blocked call is on the chain, each tied to
the accountable human behind the service account:

```sh
warden audit tail                                   # what ran, what was blocked
warden audit verify                                 # prove the chain is untampered
warden audit verify --anchor .warden/anchor.jsonl --anchor-pub anchor.pub  # + signed checkpoints
```

This is the payoff over IAM alone: IAM decides access, but it does not give you a
synchronous human hold on a specific tool call, nor a replay-proof record that
ties each executed invocation — with the full delegation chain folded into the
hash — to a named IAM principal.

## Production notes

- **DPoP (sender-constrained tokens, RFC 9449).** A bearer token can be replayed
  if stolen. Bind the token to a key the client holds: set `cnf.jkt` via
  `TokenBuilder.dpop_jkt(thumbprint)` and present a `DPoP` proof per request.
  DPoP applies on the **HTTP transport** (it needs method + URL), so use it with
  `warden proxy --http ADDR` rather than the stdio path.
- **Anchor the audit chain.** Run the proxy with
  `--anchor <file> --anchor-key <PEM>` so the chain head is periodically signed
  to a separate file; rewrites or rollbacks below a checkpoint then become
  detectable, and `warden audit verify --anchor … --anchor-pub …` checks them.
- **Sidecar vs. gateway.** Prefer a **sidecar** — one Warden per agent
  runtime/session on the MCP path — which keeps revocation surgical (pause →
  reload one process). A **shared gateway** fronting many agents is simpler to
  operate but forfeits surgical revocation and concentrates the trust boundary.
  See [Deployment patterns](../integrating/deployment.md).
- **12-factor configuration.** Drive the proxy from a `[proxy]` config table plus
  environment overrides rather than hard-coded flags; see
  [Configuration](../integrating/configuration.md).
- **Keys in Secret Manager.** The issuer/anchor private keys belong in Google
  Secret Manager (or a KMS/HSM), mounted or fetched at start — never baked into
  the image or the repo. See [Operating in production](../integrating/production.md).

## Troubleshooting

- **Actor mismatch / token rejected.** Warden's leaf actor (the deepest `act`
  `sub`) must equal the proxy's `--agent`. If you mint with `agent="prod-agent"`
  but run `--agent something-else` (or set a different `agent` on `ProxyConfig`),
  verification fails. Reconcile them, and use `warden token verify --agent … `
  to confirm.
- **ADK can't launch the proxy.** The shim resolves the binary via `warden_bin`
  → `WARDEN_BIN` → `PATH` and raises `FileNotFoundError` if none is found. Put
  `warden` on `PATH` or set `WARDEN_BIN=/abs/path/to/warden` (or
  `ProxyConfig(warden_bin=…)`) in the environment ADK spawns the toolset from.
- **ReBAC arg exactness.** `require_relation`'s `resource_arg` matches the call
  argument's value **exactly** against the `rel` tuple's resource. The example
  binds `dataViewer` to `dataset:analytics`, so the call must pass
  `dataset = "dataset:analytics"` — `"analytics"` alone will not match. Keep the
  resource-naming convention identical between `resource_bindings` (Step 1) and
  the tool's argument values.

## See also

- [The identity token](../concepts/identity-token.md) — the RFC 8693 claim model
- [Policy model](../concepts/policy.md) · [Policy reference](../reference/policy.md)
- [The audit chain](../concepts/audit.md)
- [The Python SDK](../integrating/sdk.md) — `ProxyConfig`, adapters, shims
- [Deployment patterns](../integrating/deployment.md) · [Operating in production](../integrating/production.md)
- [CLI reference](../reference/cli.md) · [Token & claims spec](../reference/token.md) · [Security & threat model](../reference/security.md)
- Sibling guides: [LangGraph](./langgraph.md) · [AWS Bedrock (AgentCore)](./aws-bedrock.md) · [Databricks (Mosaic AI)](./databricks.md)
- Runnable example: [`examples/google-adk`](https://github.com/vijayvedula/warden/tree/main/examples/google-adk)
