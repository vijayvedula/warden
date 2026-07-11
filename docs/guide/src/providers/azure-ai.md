# Azure AI Foundry

This chapter shows how to put Warden in front of the tool servers used by the
**Azure AI Foundry Agent Service**, with identity minted by **Microsoft Entra
ID**. Every `tools/call` an agent makes is verified against a signed delegation
token, evaluated against policy (allow / deny / require-approval), and appended
to a tamper-evident audit chain tied to a named Entra principal.

Azure follows the **identical token-as-interface pattern** Warden uses for the
other clouds ([Databricks](./databricks.md), [Google](./google-adk.md),
[AWS](./aws-bedrock.md)); only the four sources change — here they are Entra ID
(issuer), the agent's managed identity via OAuth 2.0 on-behalf-of (delegation),
directory / Azure RBAC (attributes and relations), and MCP (tool transport). See
[The integration model](../integrating/model.md) for the general shape.

## Overview

Warden sits as the **MCP proxy in front of the Foundry Agent Service's tool
servers**. The Foundry agent's MCP client is pointed at `warden proxy` instead
of at the tool server directly:

```
Foundry agent --(MCP)--> warden proxy --(MCP)--> tool servers
                          | verify Entra token
                          | evaluate policy (allow / deny / hold)
                          | append to tamper-evident audit chain
```

**Entra governs access; Warden governs actions + accountability.** Microsoft
Entra ID and Azure RBAC already decide *who may reach which resource*. Warden
adds the layer on top of that they do not provide for individual tool
*invocations*:

- a **synchronous human pre-authorization hold** (`require_approval`) for
  high-risk calls, and
- a **tamper-evident, per-action record** that ties every tool call back to the
  named, accountable Entra principal that stands behind the agent.

Warden's identity boundary is a single signed token carrying *who the agent acts
for*: `sub` is the accountable human, `act` is the nested acting chain whose leaf
equals the agent's wire identity, and `roles` / `attrs` / `rel` / `scope` are the
authorization claims the policy engine consumes. See
[The identity token](../concepts/identity-token.md).

## Identity mapping

The agent runs under a **managed identity** (or app registration) and acts **on
behalf of** a signed-in user through the Entra ID OBO flow. That produces
Warden's delegation chain: **user → managed identity → agent**.

| Warden claim | Azure / Entra source |
|---|---|
| `sub` (accountable human) | the signed-in user — Entra `oid` / `upn` |
| `act` (delegation chain) | user → **managed identity** (middle) → agent (leaf) |
| `roles` (RBAC) | Entra **app roles** / group claims |
| `attrs` (ABAC) | directory / resource attributes |
| `rel` (ReBAC) | **Azure RBAC** role assignments scoped to a resource (relation = `role.lower()`) |
| `scope` (agent grant) | delegated OAuth scopes on the OBO token |

The leaf of the `act` chain (`agent`) is the wire identity Warden runs the proxy
as (`--agent`). Warden's `leaf_actor` — the deepest `sub` in the chain — must
equal that value, or the call is rejected as an actor mismatch.

## Prerequisites

- **The Warden binary.** Build it from the repo (see
  [Install & build](../getting-started/install.md)):
  ```sh
  cargo build --release
  export WARDEN_BIN="$PWD/target/release/warden"   # or put `warden` on PATH
  ```
- **The Python SDK** (identity adapter + proxy helpers). The JWT signer used in
  production needs the `jwt` extra:
  ```sh
  pip install "warden-sdk[jwt]"
  ```
- **An Azure tenant** with Microsoft Entra ID, plus a **managed identity** (or
  app registration) for the agent and the app roles / Azure RBAC assignments you
  want to map into Warden claims.

The runnable example this chapter follows lives at
[`examples/azure-ai`](https://github.com/vijayvedula/warden/tree/main/examples/azure-ai).

## Step 1 — Mint a Warden token from the Entra OBO context

### The OAuth 2.0 on-behalf-of flow

When a signed-in user triggers a Foundry agent, the agent does not act as itself
alone. Through the OAuth 2.0 **on-behalf-of (OBO)** flow, the agent's managed
identity exchanges the user's token for a downstream token that still carries the
*user's* identity. That is exactly Warden's delegation model: the **user** is the
accountable `sub`, the **managed identity** is the middle `act` hop, and the
**agent** is the leaf. Entra ID is the issuer that signs the result.

### The claims-mapping adapter

`warden_sdk.adapters.azure.from_entra_obo(...)` maps a decoded Entra OBO context
to a Warden token. It is a **pure claims mapping** — it shapes claims but never
signs authority itself.

```python
from warden_sdk.adapters import azure

# A realistic decoded Entra OBO context. In production these values are NOT
# hand-written — they come from Entra ID, the agent's managed identity, and
# Azure RBAC via the OBO exchange the Foundry Agent Service performs.
entra_context = {
    "user": "alice@contoso.com",             # Entra oid/upn  -> accountable sub
    "managed_identity": "agent-mi",          # agent's MI      -> middle act
    "app_roles": ["Analyst"],                # app roles/groups-> roles (RBAC)
    "attributes": {"tenant": "contoso"},     # directory attrs -> attrs (ABAC)
    "scopes": ["Search.Query"],              # delegated scopes-> scope (grant)
    "role_assignments": [                    # Azure RBAC       -> rel (ReBAC)
        {"role": "Reader", "resource": "storage:reports"},
    ],
}

tok = azure.from_entra_obo(
    entra_context,
    agent="prod-agent",       # leaf actor == the --agent the proxy runs as
    audience="warden:azure",  # expected `aud`
    ttl_seconds=300,          # default
)
```

The exact context keys the adapter reads:

| Context key | Required | Maps to |
|---|---|---|
| `user` | **yes** | `sub` (accountable human) |
| `managed_identity` | no | middle `act` hop (`via(...)`) |
| `app_roles` (list) | no | `roles` |
| `attributes` (dict) | no | `attrs` |
| `scopes` (list) | no | `scope` |
| `role_assignments` (list of `{role, resource}`) | no | `rel` — one tuple per entry, `relation = role.lower()` |

The role assignment `{"role": "Reader", "resource": "storage:reports"}` becomes
the relation tuple `reader@storage:reports`.

### Local (dev envelope) vs. production (Entra-signed JWT)

For local development, write a **dev envelope** — an HMAC-signed token that
verifies under a shared secret so the example runs offline:

```python
from pathlib import Path

Path(".warden").mkdir(parents=True, exist_ok=True)
tok.write_dev_envelope(".warden/token.json", key="dev-secret")
```

In **production you do not sign in the mint script.** This is the
**no-forged-authority rule**: an adapter runs on the side Warden exists to police,
so it must never hold a broad-scope signing key. It orchestrates the platform's
native token exchange and asks the *issuer* to sign; Warden verifies against the
issuer's JWKS. Have **Entra ID / your IdP** issue the JWT from the OBO exchange.
When you sign locally for a controlled rollout, use the asymmetric `JwtSigner`
(Warden accepts **only** asymmetric algorithms — RS\*/PS\*/ES\*/EdDSA — which
blocks the RS256→HS256 confusion downgrade), with the private key in a KMS/HSM:

```python
from warden_sdk import JwtSigner

signer = JwtSigner.from_file("issuer.pem", "ES256", "k1")   # kid = k1
jwt = tok.to_jwt(signer, at_jwt=True)   # typ: at+jwt (RFC 9068 access token)
```

The proxy then verifies against the Entra JWKS with `--jwks-url` and `--aud`
(see Step 2).

### Verify the minted token

Run the token conformance checker the same way the proxy would, to see exactly
what Warden extracts:

```sh
warden token verify --token .warden/token.json \
  --agent prod-agent --aud warden:azure --token-key dev-secret
```

```
token OK
  accountable: alice@contoso.com
  chain:       alice@contoso.com > agent-mi > prod-agent
  roles:       Analyst
  scope:       Search.Query
  relations:   reader@storage:reports
```

For a production JWT, swap `--token-key dev-secret` for `--jwks-url <entra-jwks>`
(add `--require-at-jwt` if you set `at_jwt=True`).

## Step 2 — Route tool calls through Warden

The only integration change the Foundry agent needs is to launch `warden proxy`
instead of its tool server. The Python SDK's `ProxyConfig` builds the invocation
and the MCP client stanza:

```python
from warden_sdk import ProxyConfig

cfg = ProxyConfig(
    upstream="python3 tools_server.py",   # the Foundry tool server (stdio)
    agent="prod-agent",                   # must equal the token's leaf actor
    policy="warden.policy.toml",
    token=".warden/token.json",           # session identity (dev envelope)
    audience="warden:azure",
    audit=".warden/audit.jsonl",
    approvals=".warden/approvals.json",
)

# Feed the stanza to your MCP client (langchain_mcp_adapters / MultiServerMCPClient):
server = cfg.mcp_stdio_config()
# -> {"command": "<warden>", "args": ["proxy", "--upstream", ...], "transport": "stdio"}
```

In production, verify the Entra-signed JWT instead of the dev key:

```python
cfg = ProxyConfig(
    upstream="python3 tools_server.py",
    agent="prod-agent",
    audience="warden:azure",
    token=".warden/token.json",
    jwks_url="https://login.microsoftonline.com/<tenant>/discovery/v2.0/keys",
    issuer="https://login.microsoftonline.com/<tenant>/v2.0",
)
```

The equivalent CLI invocation:

```sh
warden proxy \
  --upstream "python3 tools_server.py" \
  --agent prod-agent \
  --policy warden.policy.toml \
  --token .warden/token.json --aud warden:azure --token-key dev-secret \
  --audit .warden/audit.jsonl \
  --approvals .warden/approvals.json
```

The proxy also serves MCP over HTTP with `--http ADDR` when the tool server or
client speaks HTTP rather than stdio.

### Shared gateway: per-request identity

`--token` binds **one** session principal to every call — the right shape for a
**sidecar** (one Warden per agent). For a **shared gateway** fronting many agents
and users, drop `--token` and use `--request-identity` so each request carries its
own verified Entra identity (`--token` and `--request-identity` are mutually
exclusive):

```python
cfg = ProxyConfig(
    upstream="python3 tools_server.py",
    agent="prod-agent",
    audience="warden:azure",
    jwks_url="https://login.microsoftonline.com/<tenant>/discovery/v2.0/keys",
    request_identity=True,        # per-request bearer identity, no session token
)
```

Sidecar is preferred (surgical revocation); the gateway trades that for simpler
operation. See [Deployment patterns](../integrating/deployment.md).

## Step 3 — Write a policy

Policy is first-matching-rule-wins; anything unmatched falls through to
`default`. The Azure-appropriate `warden.policy.toml`:

```toml
# Policy for the Azure AI Foundry Agent Service example. First matching rule
# wins; else `default`. Every call must carry a verified Entra-minted identity.

default = "deny"
require_identity = true

# Reads are allowed only for the Entra `Analyst` app role (RBAC).
[[rules]]
tool = "read_*"
decision = "allow"
require_role = "Analyst"

# Querying reports is gated on an Azure RBAC `reader` relation to the exact
# resource the call targets (ReBAC): the token must carry reader@<value of the
# call's "resource" argument>, e.g. reader@storage:reports.
[[rules]]
tool = "query_reports"
require_relation = { relation = "reader", resource_arg = "resource" }
decision = "allow"

# Destructive actions are never allowed unattended.
[[rules]]
tool = "delete_*"
decision = "deny"
reason = "destructive: agents may not delete resources"

# ABAC example — constrain a rule to a subject attribute (Entra directory attr):
# [[rules]]
# tool = "export_*"
# when = { field = "subject:tenant", op = "eq", value = "contoso" }
# decision = "require_approval"
```

What each rule does:

- **`require_identity = true`** — reject any call that does not carry a verified,
  Entra-minted identity, regardless of the tool.
- **`read_*` + `require_role = "Analyst"`** — reads are allowed only when the
  token's `roles` (mapped from Entra app roles / groups) include `Analyst`.
- **`query_reports` + `require_relation`** — the token must carry the `reader`
  relation to the *exact* resource named in the call's `resource` argument
  (`resource_arg`). If the call passes `resource = "storage:reports"`, the token
  needs `reader@storage:reports` (from an Azure RBAC `Reader` assignment on that
  resource). This is per-call, replay-proof ReBAC.
- **`delete_*` → deny** — destructive tools are refused with an explicit reason.
- The commented **ABAC** rule shows gating on a subject attribute
  (`subject:tenant`), sourced from an Entra directory attribute in `attrs`.

Swap `require_approval` for a decision on any rule to route those calls to the
human hold instead of allowing or denying outright. See the
[Policy reference](../reference/policy.md).

## Step 4 — Run & verify

Mint the token, then run the agent's tool calls through the proxy (Steps 1–2).
Each `tools/call` is verified, evaluated, and recorded. Inspect the audit chain:

```sh
# Every call: which tool, allowed/blocked, and the accountable principal behind it.
warden audit tail --audit .warden/audit.jsonl

# Prove the record has not been tampered with (hash-chain integrity).
warden audit verify --audit .warden/audit.jsonl
```

Because the delegation chain is folded into each record, every line ties back to
a **named Entra principal** — `alice@contoso.com`, acting through `agent-mi` and
`prod-agent` — not to an anonymous service identity. That is the "could the
accountable human have known/authorized this, and can we prove it" property.

If a rule is `require_approval`, the call is held; a human releases it out of
band:

```sh
warden approvals list
warden approve <id> --by security@contoso.com --approver-key approver.pem
```

## Production notes

- **DPoP sender-constraint (RFC 9449).** Bind the token to a proof key so a
  stolen bearer token cannot be replayed. Add `cnf.jkt` at mint time with
  `TokenBuilder.dpop_jkt(jkt)` (compose it into the mapped token before signing);
  the HTTP gateway then requires a matching DPoP proof on each request.
- **Anchored audit.** For rollback-proof audit, periodically anchor the chain:
  `--anchor .warden/anchor.jsonl --anchor-key anchor.pem`. Verify later with
  `warden audit verify --anchor .warden/anchor.jsonl --anchor-pub anchor.pub`.
- **SIEM export.** Emit OCSF-shaped events for Microsoft Sentinel / your SIEM
  with `--ocsf .warden/events.ocsf.jsonl`.
- **Sidecar vs. gateway.** Prefer one Warden per agent session (surgical
  revocation via pause→reload); adopt the shared gateway (`--request-identity`)
  only when you need one process fronting many agents. See
  [Deployment patterns](../integrating/deployment.md).
- **12-factor config.** Drive the proxy from a `[proxy]` TOML table or
  environment (`WARDEN_BIN`, `--config FILE`) so nothing is baked into images.
  See [Configuration (12-factor)](../integrating/configuration.md) and
  [Operating in production](../integrating/production.md).
- **Keys in Azure Key Vault.** Keep the issuer's signing key and any anchor /
  approver keys in **Azure Key Vault** (or an HSM), never on the agent host — the
  no-forged-authority rule is only as strong as the key custody behind it.

## Troubleshooting

- **Actor mismatch / token rejected.** Warden's leaf actor (deepest `sub` in the
  `act` chain) must equal the proxy's `--agent`. If you minted with
  `agent="prod-agent"`, run the proxy with `--agent prod-agent`. Confirm the
  chain with `warden token verify` (`chain: ... > prod-agent`).
- **Missing / wrong `aud`.** If verification fails on audience, the token's `aud`
  and the proxy's `--aud` disagree. Pass `audience="warden:azure"` to
  `from_entra_obo(...)` and `--aud warden:azure` to the proxy. Entra access
  tokens set `aud` to the target resource/app ID URI — make the two match, or set
  the audience explicitly on the mapped token.
- **OBO token exchange nuances.** The OBO exchange must request the **delegated
  scopes** you map into `scope` and must preserve the user identity (`oid`/`upn`)
  as `sub` — if the downstream token comes back as an app-only (client
  credentials) token, there is no accountable human and `require_identity` will
  fail. Ensure the managed identity has the app roles / Azure RBAC assignments you
  reference; those are the *source* for `roles` and `rel`, and a missing
  assignment shows up as a denied `require_role` / `require_relation` rule, not a
  token error.
- **`require_relation` denials.** The relation is `role.lower()@<resource>`, and
  the resource must match the call's `resource_arg` value exactly. `Reader` on
  `storage:reports` yields `reader@storage:reports`; a call passing a different
  `resource` string will not match.
- **HS256 rejected.** Warden accepts only asymmetric JWT algorithms. Sign with
  `ES256`/`RS256`/`EdDSA` via `JwtSigner`, not an HMAC secret (dev envelopes are
  the only symmetric path, and only under `--token-key`).

## See also

- [`examples/azure-ai`](https://github.com/vijayvedula/warden/tree/main/examples/azure-ai)
  — the runnable example this chapter follows.
- [The integration model](../integrating/model.md) and
  [The Python SDK](../integrating/sdk.md) — the token-as-interface pattern and
  adapter/proxy helpers.
- [Deployment patterns](../integrating/deployment.md),
  [Configuration (12-factor)](../integrating/configuration.md),
  [Operating in production](../integrating/production.md).
- Sibling provider guides: [Databricks](./databricks.md),
  [Google ADK / Vertex AI](./google-adk.md),
  [AWS Bedrock (AgentCore)](./aws-bedrock.md), [LangGraph](./langgraph.md).
- Reference: [CLI](../reference/cli.md), [Policy](../reference/policy.md),
  [Token & claims spec](../reference/token.md),
  [Security & threat model](../reference/security.md).
- Concepts: [The identity token](../concepts/identity-token.md).
