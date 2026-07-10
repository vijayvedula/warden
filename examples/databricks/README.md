# Databricks + Warden — Unity Catalog adoption example

Put Warden in front of your Databricks agent's tools so every `tools/call` is
checked against policy (allow / deny / require-approval) and recorded in a
tamper-evident audit chain — with every action tied to the **named human** who
triggered the agent, not just the service principal.

```
Mosaic AI agent --(MCP)--> Warden --(MCP, stdio subprocess)--> UC-function tools
                             | verify token / policy / hold / audit
```

## Where Warden sits

The agent runs inside Databricks — a Mosaic AI Agent, a Databricks-hosted MCP
server in **Model Serving**, or a **Databricks App**. Its MCP client is pointed
at **`warden proxy ...`** instead of the UC-function tool server, so the proxy
governs every Unity Catalog function call (`read_table`, `query_table`, ...)
before it executes. No other agent code is Warden-aware.

## What mints the token

The agent runs as a **service principal** using **on-behalf-of-user (OBO)**
auth. That gives Warden the RFC 8693 delegation chain it needs:

- `sub` = the OBO **user** (the accountable human)
- `act` = **service principal** → **agent** (the leaf actor equals the agent's
  wire identity, `--agent prod-agent`)
- `roles` = the user's **Unity Catalog group** membership (RBAC)
- `attrs` = workspace / catalog context (ABAC)
- `rel` = **UC grants** on securables (ReBAC; relation is the privilege
  lower-cased, e.g. `SELECT` → `select`)
- `scope` = the registered UC functions the agent may invoke

The `databricks.from_obo(...)` adapter only **shapes** these claims — it never
signs authority (the no-forged-authority rule). For dev this example writes a
symmetric **dev envelope**; in production the platform's issuer / KMS signs a
real JWT and the proxy verifies it. See
[`mint_token.py`](./mint_token.py) and
[`../../sdk/python/`](../../sdk/python/).

## Why the ReBAC grant mapping matters

Mapping UC grants to `rel` tuples lets a single policy rule enforce *"the agent
may call this UC function only on tables the user can read"* at the action
boundary:

```toml
[[rules]]
tool = "query_table"
require_relation = { relation = "select", resource_arg = "table" }
decision = "allow"
```

Warden reads the `table` argument of the incoming call and requires a matching
`select@<table>` tuple in the **signed token**. Because the grant lives in the
token — not in a header the agent controls — it is spoof-proof and **replay-proof**:
a captured request can't widen access, and the token expires (300s TTL here).

## Three steps

### 1. Mint a token

```sh
cd examples/databricks
python mint_token.py alice@example.com      # writes .warden/token.json (dev envelope)

# sanity-check it (leaf actor == prod-agent, audience, dev signature):
warden token verify --token .warden/token.json \
  --agent prod-agent --aud warden:databricks --token-key dev-secret   # -> "token OK"
```

### 2. Run the proxy in front of your UC-function tools

Point the agent's MCP client at the proxy. With the SDK:

```python
from warden_sdk import ProxyConfig
cfg = ProxyConfig(
    upstream="python3 uc_tools_server.py",
    agent="prod-agent",
    token=".warden/token.json",
    audience="warden:databricks",
)
cfg.command()            # -> the full `warden proxy ...` argv
cfg.mcp_stdio_config()   # -> an MCP stdio stanza your MCP client can consume
```

Or invoke the CLI directly:

```sh
warden proxy --upstream "python3 uc_tools_server.py" --agent prod-agent \
  --policy warden.policy.toml --token .warden/token.json --aud warden:databricks \
  --audit .warden/audit.jsonl
```

Now `read_table` is allowed for the `analysts` role, `query_table` succeeds only
on tables the token holds a `select` grant for, and `drop_table` is denied.

### 3. Verify the audit trail

```sh
warden audit tail   --audit .warden/audit.jsonl   # what ran / what was blocked
warden audit verify --audit .warden/audit.jsonl   # prove the chain is untampered
```

## Production

Instead of the dev envelope, sign a real JWT with the Databricks token issuer /
your KMS — the adapter shapes claims, the issuer signs them:

```python
from warden_sdk import JwtSigner
jwt = tok.to_jwt(JwtSigner.from_file("issuer.pem", "ES256", "k1"), at_jwt=True)
```

Then run the proxy with `--jwks-url <issuer-jwks>` and `--aud warden:databricks`
so it verifies the signature and audience on every call (Warden accepts only
asymmetric algorithms, blocking the RS256→HS256 downgrade). Add `--request-identity`
to fail closed when a call arrives without a verified token — matching
`require_identity = true` in [`warden.policy.toml`](./warden.policy.toml).

See [`../../docs/platform-integration.md`](../../docs/platform-integration.md)
(Sec 3, Databricks / Mosaic AI Agent Framework / Unity Catalog) and the SDK in
[`../../sdk/python/`](../../sdk/python/).
