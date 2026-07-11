# Databricks (Mosaic AI)

This guide governs a **Mosaic AI Agent Framework** agent that calls **Unity
Catalog function tools** (or a Databricks-hosted MCP server) with Warden. You
put Warden in front of the agent's tools so every `tools/call` is checked
against policy (allow / deny / require-approval), high-risk calls can be held
for a human, and every action lands in a tamper-evident audit chain — tied to
the **named human** who triggered the agent, not just the service principal it
runs as.

The whole integration is one signed token plus one proxy process. No agent code
becomes Warden-aware.

## Overview

The agent runs inside Databricks — a Mosaic AI Agent, a Databricks-hosted MCP
server in **Model Serving**, or a **Databricks App**. Point its MCP client at
`warden proxy ...` instead of at the Unity Catalog tool server, and the proxy
governs every UC function call before it executes.

```
Mosaic AI agent --(MCP)--> warden proxy --(MCP)--> UC function tools / Databricks MCP
                             |
                             +-- verify token -> policy -> hold -> audit
```

**Unity Catalog governs the data layer; Warden governs the action layer.**
Unity Catalog already owns lineage, table/function grants, and tags — the *data*
governance. Warden does not duplicate any of that. Instead it consumes UC's
grants as the *source* for its relationship claims and adds what UC has no notion
of for tool *invocations*:

- **pre-authorization holds** — pause a high-risk call for a human before it runs,
- **per-run budgets** — cap what one agent run may do,
- a **tamper-evident, hash-chained recorder** that ties each UC tool call back to
  the accountable human — the accountability record UC lineage does not provide
  for tool invocations.

So the division of labor is clean: UC says *which data this user may read*;
Warden says *whether this agent may take this action, right now, on that user's
behalf* — and proves it later.

## Identity mapping

The agent runs as a **service principal** using **on-behalf-of-user (OBO)**
authentication. Databricks hands the serving environment the accountable human
(the OBO user), the service principal, the user's Unity Catalog group
membership, the workspace/catalog context, and — from Unity Catalog — which
grants the user holds on which securables. The
[`databricks.from_obo(...)`](https://github.com/vijayvedula/warden/tree/main/sdk/python/warden_sdk/adapters/databricks.py)
adapter *shapes* all of that into Warden's canonical claims. It never signs
authority (see the [no-forged-authority rule](#the-no-forged-authority-rule)).

| Warden claim | Meaning | Databricks source |
|---|---|---|
| `sub` | accountable human | OBO **user** principal |
| `act` | delegation chain (leaf = agent) | **service principal** → **agent** |
| `roles` (RBAC) | group membership | user's **Unity Catalog groups** |
| `attrs` (ABAC) | environment context | **workspace** / **catalog** |
| `rel` (ReBAC) | relationships on resources | **UC grants** on securables (relation = privilege lower-cased) |
| `scope` | what the agent may invoke | registered **UC functions** for this agent |

The delegation chain reads *human → service principal → agent*: the OBO user is
the accountable `sub`, the service principal is the middle `act` hop, and the
agent (`--agent prod-agent`) is the **leaf actor**. Warden requires the leaf of
the `act` chain to equal the `--agent` the proxy runs as, so the token cannot be
replayed under a different agent identity.

The ReBAC mapping is the interesting one: a Unity Catalog `SELECT` grant on
`table:main.sales` becomes the tuple `select@table:main.sales` in the **signed
token**. That lets a single policy rule enforce *"the agent may call this UC
function only on tables the user can actually read"* at the action boundary —
spoof-proof (the grant lives in the token, not a wire header the agent controls)
and replay-proof (the token expires).

For the full claim model see [the identity token](../concepts/identity-token.md)
and the [token & claims spec](../reference/token.md).

## Prerequisites

- **Build Warden** (the Rust proxy binary) and put it on `PATH`, or set
  `WARDEN_BIN`. See [Install & build](../getting-started/install.md).
- **Install the SDK** into the agent's environment:

  ```sh
  pip install warden-sdk          # token builder + adapters + ProxyConfig
  pip install "warden-sdk[jwt]"   # add this for production JWT signing (JwtSigner)
  ```

- **A Databricks workspace** with Unity Catalog enabled, a **service principal**
  for the agent runtime, and on-behalf-of-user auth configured for it. You will
  also need the UC group membership and grants for the users the agent acts for.

The example this guide follows lives at
[`examples/databricks`](https://github.com/vijayvedula/warden/tree/main/examples/databricks).

## Step 1 — Mint a Warden token from the OBO context

In production the values below come straight from the Databricks runtime — the
OBO identity and Unity Catalog metadata available in the agent's serving
environment. The adapter maps them to canonical claims:

```python
from warden_sdk.adapters import databricks

# Populated from the Databricks OBO identity + Unity Catalog metadata.
obo_context = {
    "user": "alice@example.com",               # OBO user   -> accountable sub
    "service_principal": "sp-agent-runtime",    # svc princ  -> middle act hop
    "uc_groups": ["analysts"],                 # UC groups  -> roles (RBAC)
    "workspace": "ws-123",                     # workspace  -> attrs (ABAC)
    "catalog": "main",                         # catalog    -> attrs (ABAC)
    "uc_grants": [                             # UC grants  -> rel (ReBAC)
        {"privilege": "SELECT", "securable": "table:main.sales"},
    ],
    "tools": ["read_table", "query_table"],    # UC functions -> scope
}

tok = databricks.from_obo(
    obo_context,
    agent="prod-agent",         # the leaf actor / agent wire identity
    audience="warden:databricks",
    ttl_seconds=300,            # short-lived; default is 300s
)
```

`from_obo` returns a `TokenBuilder`. `context["user"]` is **required** (it is the
accountable `sub`); every other key is optional and simply omitted from the
claims if absent.

### Dev envelope (local runs)

For local development, write a symmetric **dev envelope** — a `{"claims": {...},
"sig": ...}` file whose signature verifies under a shared `--token-key`. This is
a development convenience, not an enforcement mode.

```python
import os
os.makedirs(".warden", exist_ok=True)
tok.write_dev_envelope(".warden/token.json", key="dev-secret")
```

Or run the example script directly:

```sh
cd examples/databricks
python mint_token.py alice@example.com     # writes .warden/token.json (dev envelope)
```

### Production JWT (signed by Databricks / your IdP)

In production the adapter still only shapes the claims — the **trusted signer is
the platform issuer / KMS**, not the SDK. Sign the shaped claims as a real
asymmetric JWT with `JwtSigner`, then have the proxy verify it against the
issuer's JWKS:

```python
from warden_sdk import JwtSigner

# The private key lives in a KMS / Databricks secret scope — never in agent code.
signer = JwtSigner.from_file("issuer-es256.pem", "ES256", default_kid="k1")
jwt = tok.to_jwt(signer, at_jwt=True)   # compact JWT; at+jwt per RFC 9068
```

Warden accepts **only asymmetric algorithms** (RS*/PS*/ES*/EdDSA), which blocks
the RS256→HS256 confusion downgrade (an HS256 token forged with the public key is
rejected). The proxy then verifies each call:

```sh
warden proxy ... \
  --jwks-url https://<issuer>/.well-known/jwks.json \
  --aud warden:databricks \
  --iss https://<issuer> \
  --request-identity        # fail closed on any call with no verified token
```

Because `to_jwt(..., at_jwt=True)` marks the token `typ: at+jwt`, you can also
require that shape at the proxy with `--require-at-jwt`.

### The no-forged-authority rule

From Warden's point of view the adapter is **untrusted client code** — it runs on
the side Warden exists to police. So the adapter *orchestrates* Databricks'
native token exchange and *shapes* claims; it never holds a broad-scope signing
key of its own. The trusted signer stays the platform issuer (Databricks token
issuer / your IdP / KMS), and the proxy verifies against that issuer's JWKS. Done
this way the SDK adds convenience with **no new trust surface**.

### Verify the token

Sanity-check the minted token — leaf actor equals `prod-agent`, audience
matches, signature valid:

```sh
warden token verify --token .warden/token.json \
  --agent prod-agent --aud warden:databricks --token-key dev-secret   # -> "token OK"
```

## Step 2 — Route tool calls through Warden

Point the agent's MCP client at the proxy instead of the UC-tools server. The
`ProxyConfig` helper builds the exact `warden proxy` invocation and an MCP stdio
stanza your client can consume:

```python
from warden_sdk import ProxyConfig

cfg = ProxyConfig(
    upstream="python3 uc_tools_server.py",   # your UC-function MCP tool server
    agent="prod-agent",                      # must equal the token's leaf actor
    policy="warden.policy.toml",
    token=".warden/token.json",              # dev envelope; omit when using JWKS
    audience="warden:databricks",
    audit=".warden/audit.jsonl",
    request_identity=True,                   # -> --request-identity (fail closed)
)

cfg.command()           # -> full `warden proxy ...` argv (resolves the binary)
cfg.mcp_stdio_config()  # -> {"command", "args", "transport": "stdio"} for an MCP client
```

For a production JWT flow, drop `token=` and set `jwks_url=` / `issuer=` instead
so the proxy verifies every call against the issuer:

```python
cfg = ProxyConfig(
    upstream="python3 uc_tools_server.py",
    agent="prod-agent",
    policy="warden.policy.toml",
    audience="warden:databricks",
    jwks_url="https://<issuer>/.well-known/jwks.json",
    issuer="https://<issuer>",
    request_identity=True,
)
```

## Step 3 — Write a policy

A Databricks-appropriate policy: fail closed on missing identity, allow reads for
the `analysts` UC group, gate the `query_table` UC function on a ReBAC `select`
relation to *the table it was asked to query*, and deny destructive DDL
outright. First matching rule wins; otherwise `default`.

```toml
# warden.policy.toml — Databricks / Unity Catalog UC-function tools.
default = "deny"
require_identity = true    # fail closed: reject any call without a verified token

# Reads are allowed for the `analysts` UC group (RBAC). The role is carried in
# the signed token (mapped from Unity Catalog group membership), not asserted by
# the agent, so it cannot be spoofed on the wire.
[[rules]]
tool = "read_*"
decision = "allow"
require_role = "analysts"

# A UC function that queries a specific table is gated on a ReBAC `select`
# relation to *that* table. `query_table` is allowed only when the token carries
# `rel = select@<value of the "table" arg>` — i.e. only on tables the OBO user
# can actually read in Unity Catalog. Enforced at the action boundary and
# replay-proof: the tuple lives in the signed token.
[[rules]]
tool = "query_table"
require_relation = { relation = "select", resource_arg = "table" }
decision = "allow"

# Destructive DDL is never allowed unattended, regardless of grants.
[[rules]]
tool = "drop_table"
decision = "deny"
reason = "destructive: agents may not drop Unity Catalog tables"
```

`resource_arg = "table"` tells Warden to read the incoming call's `table`
argument and require a matching `select@<that value>` tuple in the token. Because
that tuple was minted from the OBO user's Unity Catalog grant, the rule enforces
UC's data boundary at the tool-call boundary.

You can tighten further with ABAC `when` conditions or hold large operations for
a human:

```toml
# Restrict reads to the `main` catalog only (ABAC on a signed attr).
[[rules]]
tool = "read_*"
require_role = "analysts"
when = { field = "subject:catalog", op = "eq", value = "main" }
decision = "allow"

# Hold large exports for human sign-off (pre-authorization hold).
[[rules]]
tool = "export_table"
when = { arg = "row_limit", op = "gt", value = 1000000 }
decision = "require_approval"
reason = "large export requires human sign-off"
```

See the [policy model](../concepts/policy.md) and the
[policy reference](../reference/policy.md) for the full rule grammar.

## Step 4 — Run & verify

Run the proxy directly, or launch the argv from `ProxyConfig.command()`:

```sh
warden proxy --upstream "python3 uc_tools_server.py" --agent prod-agent \
  --policy warden.policy.toml --token .warden/token.json --aud warden:databricks \
  --request-identity --audit .warden/audit.jsonl
```

With this policy: `read_table` is allowed for the `analysts` role, `query_table`
succeeds only on tables the token holds a `select` grant for, and `drop_table` is
denied.

Then inspect and verify the audit chain:

```sh
warden audit tail   --audit .warden/audit.jsonl   # what ran / what was blocked
warden audit verify --audit .warden/audit.jsonl   # prove the chain is untampered
```

Each record ties a UC tool *invocation* to the accountable human via the full
delegation chain (`sub` → service principal → agent) — the accountability record
Unity Catalog lineage does not provide for tool calls. `audit verify` recomputes
the hash chain and fails if any entry was altered or removed. See
[the audit chain](../concepts/audit.md).

## Production notes

- **DPoP** — bind the token to a proof-of-possession key so a stolen token cannot
  be replayed from another host. Set `cnf.jkt` when minting
  (`TokenBuilder.dpop_jkt(...)`) and require the proof at the proxy. See
  [Operating in production](../integrating/production.md).
- **Anchor the audit chain** — periodically `--anchor` the chain head to a WORM
  store or your SIEM so tampering is detectable even if the local file is
  compromised.
- **Sidecar vs. shared gateway** — prefer one Warden per agent runtime/session on
  the MCP path (surgical pause-and-reload revocation), or a shared gateway
  fronting many agents when operational simplicity outweighs fine-grained
  revocation. Trade-offs in [Deployment patterns](../integrating/deployment.md).
- **12-factor config** — every proxy flag has an environment-variable equivalent,
  so the same image runs across workspaces with config injected at deploy time.
  See [Configuration (12-factor)](../integrating/configuration.md).
- **Keys in a secret scope** — keep the JWT signing private key in a Databricks
  **secret scope** / KMS, never in agent code or the image. The proxy only needs
  the public JWKS URL.

## Troubleshooting

- **`actor mismatch` / leaf-actor rejection** — the token's leaf `act.sub` does
  not equal the proxy's `--agent`. The service principal is the *middle* hop; the
  agent (`prod-agent`) must be the leaf. Confirm with `warden token verify
  --agent prod-agent ...` and check `via(service_principal)` was called before
  the agent was set as leaf.
- **ReBAC rule denies a call you expected to allow** — the call's `resource_arg`
  value must equal the token's `rel` resource **string exactly**. The token holds
  `select@table:main.sales`; the `table` argument must be exactly
  `table:main.sales` (same securable prefix, catalog, and name). A bare
  `main.sales` or `sales` will not match.
- **Every call is denied with no matching rule** — `default = "deny"` plus
  `require_identity = true` fails closed. Make sure a verified token is reaching
  the proxy (`--token` for dev envelopes, or `--jwks-url`/`--aud` for JWTs) and
  that `--request-identity` is paired with a valid token source.
- **JWT rejected** — Warden accepts only asymmetric algorithms; an HS256 token is
  refused. Check `--aud` and `--iss` match the token's `aud`/`iss`, and that the
  signing `kid` is present in the JWKS.

## See also

- [The identity token](../concepts/identity-token.md) · [Policy model](../concepts/policy.md) · [The audit chain](../concepts/audit.md)
- [Deployment patterns](../integrating/deployment.md) · [Configuration (12-factor)](../integrating/configuration.md) · [Operating in production](../integrating/production.md)
- [The Python SDK](../integrating/sdk.md)
- [Policy reference](../reference/policy.md) · [Token & claims spec](../reference/token.md) · [CLI reference](../reference/cli.md)
- Sibling provider guides: [LangGraph](./langgraph.md) · [AWS Bedrock (AgentCore)](./aws-bedrock.md) · [Google ADK / Vertex AI](./google-adk.md) · [Azure AI Foundry](./azure-ai.md)
- Example: [`examples/databricks`](https://github.com/vijayvedula/warden/tree/main/examples/databricks) — [`README.md`](https://github.com/vijayvedula/warden/tree/main/examples/databricks/README.md), [`mint_token.py`](https://github.com/vijayvedula/warden/tree/main/examples/databricks/mint_token.py), [`warden.policy.toml`](https://github.com/vijayvedula/warden/tree/main/examples/databricks/warden.policy.toml)
- Background: [Integrating Warden with agentic platforms](https://github.com/vijayvedula/warden/tree/main/docs/platform-integration.md) (Sec 3)
