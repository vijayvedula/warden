# LangGraph

[LangGraph](https://github.com/langchain-ai/langgraph) is an orchestration
framework: it wires an LLM into a graph of tool-calling steps. It has **no
identity issuer of its own** — a LangGraph app has no `sub` to anchor to; it
runs on top of a cloud (AWS, Databricks, Google, Azure) or on-prem. Governing it
with Warden therefore *composes two things*:

- an **orchestration shim** — route the agent's tool calls through `warden
  proxy` (this chapter), and
- an **identity adapter** — mint the Warden token from wherever the agent runs
  (see [AWS Bedrock](./aws-bedrock.md), [Databricks](./databricks.md),
  [Google ADK / Vertex AI](./google-adk.md), or [Azure AI Foundry](./azure-ai.md)).

This is the split described in the [integration model](../integrating/model.md):
the token is the only interface, and orchestration shims pair with identity
adapters rather than replacing them. For a purely local / on-prem run you can
skip the cloud adapter and use a dev-envelope token (Step 2).

LangGraph is also the one example that runs **fully end-to-end on your laptop** —
the agent reads a table (allowed) and tries to drop a database (blocked) — so
this guide is runnable start to finish. The complete sources live at
[`examples/langgraph`](https://github.com/vijayvedula/warden/tree/main/examples/langgraph).

## Overview

The only integration change is where the agent's MCP client points: instead of
launching the tool server directly, it launches `warden proxy`, which launches
the tool server as its upstream and governs every `tools/call`.

```
LangGraph agent --(MCP, stdio)--> warden proxy --(MCP, stdio subprocess)--> tools_server.py
                                       |
                                       | verify identity -> policy -> hold -> audit
                                       v
                                  allow / deny / require-approval
```

No other agent code becomes Warden-aware. The graph, the model, the tools —
unchanged. Warden sits on the wire, verifies the delegation token, evaluates
policy on each call, holds high-risk calls for a human, and records a
tamper-evident audit chain. The proxy always accepts a raw conforming token; the
[Python SDK](../integrating/sdk.md) is convenience for building the command and
the MCP client stanza.

## Prerequisites

```sh
# 1. Build Warden (from the repo root -> target/release/warden)
cargo build --release
export PATH="$PWD/target/release:$PATH"

# 2. Python deps: the SDK, LangGraph, the MCP adapter, the model, and MCP itself
pip install warden-agent-sdk langgraph langchain-mcp-adapters langchain-anthropic mcp

# 3. The agent's model key
export ANTHROPIC_API_KEY=sk-ant-...
```

Confirm `warden` is reachable:

```sh
warden --help    # or: ./target/release/warden --help
```

The example ships a tiny MCP tool server, `tools_server.py`, exposing three
tools chosen to demonstrate the three policy decisions:

| Tool | Nature | Policy decision |
|---|---|---|
| `read_records` | read-only | allow |
| `create_ticket` | outbound side effect | require_approval |
| `delete_database` | destructive | deny |

## Step 1 — Route tool calls through Warden

The entire orchestration change is swapping the MCP client's target. Below is
the *before* (agent talks to the tool server directly, ungoverned) and *after*
(agent talks to Warden, which talks to the tool server).

**Before — ungoverned:**

```python
from langchain_mcp_adapters.client import MultiServerMCPClient

client = MultiServerMCPClient({
    "tools": {
        "command": "python3",
        "args": ["tools_server.py"],
        "transport": "stdio",
    }
})
```

**After — every call routed through `warden proxy`:**

```python
from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain_anthropic import ChatAnthropic
from langgraph.prebuilt import create_react_agent

from warden_sdk import ProxyConfig
from warden_sdk.orchestration import langgraph as wl

# Describe the `warden proxy` invocation in front of the tool server.
cfg = ProxyConfig(
    upstream="python3 tools_server.py",   # Warden launches this as its upstream
    agent="demo-agent",                   # the agent's wire identity (leaf actor)
    policy="warden.policy.toml",
    audit=".warden/audit.jsonl",
    approvals=".warden/approvals.json",
    log_format="json",
)

# warden_mcp_servers(cfg) -> {"tools": {"command": <warden>, "args": [...], "transport": "stdio"}}
client = MultiServerMCPClient(wl.warden_mcp_servers(cfg))

tools = await client.get_tools()          # discovered THROUGH Warden
model = ChatAnthropic(model="claude-sonnet-4-6")
agent = create_react_agent(model, tools)
```

`ProxyConfig` builds the `warden proxy ...` argument vector;
`warden_mcp_servers(cfg)` wraps `cfg.mcp_stdio_config()` in the
`MultiServerMCPClient` shape. (If you prefer, `wl.warden_stdio_client(cfg)`
constructs the `MultiServerMCPClient` for you.) The agent object and the graph
are exactly what you would write without Warden — only the client stanza
changed.

> If `warden` is not on `PATH`, set `WARDEN_BIN=/path/to/warden` or pass
> `ProxyConfig(..., warden_bin="../../target/release/warden")`.

## Step 2 — Add accountability (a token)

By default the example runs without identity so you can see policy work
immediately. To make every action tie to a named human, add a **delegation
token**: `sub` is the accountable human, `act` is the nested acting chain whose
leaf equals the agent's wire identity (`--agent`), plus `roles` (RBAC), `attrs`
(ABAC), `rel` (ReBAC), and `scope` (the agent's grant). See
[the identity token](../concepts/identity-token.md) for the full model.

For a local walkthrough, mint a **dev-envelope** token with `TokenBuilder`
(this is what `examples/langgraph/mint_token.py` does):

```python
from warden_sdk import TokenBuilder

tok = (
    TokenBuilder(sub="alice@example.com", agent="demo-agent")
    .role("data.reader")
    .grant("read_records", "create_ticket")
    .audience("warden:langgraph")
    .expires_in(3600)
)
tok.write_dev_envelope(".warden/token.json", key="dev-secret")
```

```sh
python3 mint_token.py alice@example.com
```

Verify the token the way the proxy would (a conformance check — it prints the
delegation chain and exits nonzero if the token does not verify):

```sh
warden token verify \
  --token .warden/token.json \
  --agent demo-agent \
  --aud warden:langgraph \
  --token-key dev-secret
```

Then attach it to the proxy. With `ProxyConfig` the token, audience, and dev key
flow into the command:

```python
cfg = ProxyConfig(
    upstream="python3 tools_server.py",
    agent="demo-agent",
    policy="warden.policy.toml",
    token=".warden/token.json",
    audience="warden:langgraph",
    extra_args=["--token-key", "dev-secret"],   # dev only; production uses --jwks-url
)
```

> **Dev tokens are not an enforcement mode.** `--token-key` verifies a symmetric
> dev signature — fine for a laptop, tests, and the conformance kit. In
> production the token is a real JWT signed by the platform's issuer/KMS, and
> Warden verifies it against the issuer's JWKS (`--jwks-url` / `--aud`). The
> adapter *shapes* claims and asks the issuer to sign; it never signs authority
> itself. That is the job of the identity adapter for your cloud — see
> [AWS Bedrock](./aws-bedrock.md), [Databricks](./databricks.md),
> [Google ADK / Vertex AI](./google-adk.md), or [Azure AI Foundry](./azure-ai.md).

## Step 3 — Write a policy

A LangGraph-appropriate policy: allow reads, deny destructive actions outright,
and hold outbound side effects for a human. First matching rule wins; otherwise
the `default`. See the [policy reference](../reference/policy.md) for the full
grammar.

```toml
# warden.policy.toml — first matching rule wins; else `default`.
default = "deny"

# Require a verified human behind every action (fail closed without a token).
require_identity = true

# Reads are safe.
[[rules]]
tool = "read_*"
require_role = "data.reader"
decision = "allow"

# Outbound side effects wait for a human (warden approve <id> --by you).
[[rules]]
tool = "create_ticket"
decision = "require_approval"
reason = "ticket creation requires human approval"

# Destructive actions are never allowed unattended.
[[rules]]
tool = "delete_database"
decision = "deny"
reason = "destructive: agents may not drop databases"
```

`require_identity = true` makes Warden fail closed unless a verified token is
present, so the accountability chain is never optional. To run the example
without a token first (to see policy alone), leave `require_identity` off — the
shipped [`warden.policy.toml`](https://github.com/vijayvedula/warden/tree/main/examples/langgraph)
does exactly that and drops the `require_role` clause. Turn it on once you have
completed Step 2. You can layer RBAC/ABAC/ReBAC on top with `require_role`,
`when` clauses over `subject:`/`resource:` attributes, and relationship checks.

## Step 4 — Run it

```sh
cd examples/langgraph
python3 agent.py
```

The bundled `agent.py` prompts the model to *"First read the 'customers' table.
Then drop the 'prod' database to free up space."* You will watch two decisions
flow through Warden:

1. `read_records(table="customers")` — **allowed**. The tool result comes back:
   `read 3 records from customers`.
2. `delete_database(name="prod")` — **blocked before it reaches the tool**. The
   agent receives a clean tool error:
   `BLOCKED by Warden: destructive: agents may not drop databases`.

The model then reports what happened with each step. The destructive call never
touched `tools_server.py` — Warden denied it on the wire and recorded the
attempt.

## Step 5 — Verify what the agent did

Every decision is appended to a hash-chained, tamper-evident audit log. Inspect
and verify it (see [the audit chain](../concepts/audit.md)):

```sh
warden audit tail   --audit .warden/audit.jsonl   # read_records=executed, delete_database=blocked
warden audit verify --audit .warden/audit.jsonl   # prove the chain is untampered
```

`audit tail` shows each `tools/call`, its decision, and — when identity is on —
the accountable `sub` and the acting chain. `audit verify` recomputes the hash
chain and reports any break. In production, add signed checkpoints and verify
them too (Production notes).

## Human-in-the-loop

`create_ticket` is `require_approval`, so a call to it **holds** rather than
executing: Warden pauses that `tools/call` and records a pending approval
instead of forwarding it. Point the agent at `create_ticket` (or add it to the
prompt) and, from a second terminal, release it:

```sh
warden approvals list --approvals .warden/approvals.json
# 3f2a...  create_ticket {"title":"..."}  (ticket creation requires human approval)

warden approve 3f2a... --by you --approvals .warden/approvals.json
```

Once approved, the held call proceeds and its result returns to the agent; the
approval (and who granted it) is written into the audit chain. `warden deny <id>
--by you` rejects it instead. For a cryptographically-bound approval, pass
`--approver-key <PEM>` so the approver signs an assertion over the exact action.

## Production notes

Everything above runs locally; hardening for production is additive — the agent
code does not change, only the proxy flags and the token source.

- **Verified identity.** Replace the dev key with real JWT verification: launch
  the proxy with `--jwks-url https://idp/.well-known/jwks.json` and `--aud
  warden:prod`, and keep `require_identity = true`. The token now comes from your
  cloud's identity adapter (STS session, Databricks OBO, workload identity,
  Entra), not from `mint_token.py`.

  ```python
  cfg = ProxyConfig(
      upstream="python3 tools_server.py",
      agent="prod-agent",
      policy="warden.policy.toml",
      token=".warden/token.json",
      audience="warden:prod",
      jwks_url="https://idp/.well-known/jwks.json",
  )
  ```

- **Evidence.** Add tamper-evident checkpoints and SIEM export via
  `extra_args`: `--anchor .warden/anchor.jsonl --anchor-key anchor.pem`
  (rollback-proof signed checkpoints) and `--ocsf .warden/ocsf.jsonl`
  (OCSF events for your SIEM). Verify with
  `warden audit verify --anchor .warden/anchor.jsonl --anchor-pub anchor.pub`.

- **Deployment topology.** The example is a **sidecar-per-agent** (one `warden
  proxy` per agent process, on the stdio path) — preferred, because revocation
  is surgical (pause/reload one process). A **shared HTTP gateway** (one Warden
  fronting many agents, `--http ADDR`) is simpler to operate but concentrates the
  trust boundary. See [deployment patterns](../integrating/deployment.md).

- **Configuration.** All flags have 12-factor `WARDEN_*` environment-variable
  equivalents (e.g. `WARDEN_JWKS_URL`, `WARDEN_AUD`, `WARDEN_POLICY`), so you can
  keep secrets and endpoints out of code. See
  [configuration](../integrating/configuration.md) and
  [operating in production](../integrating/production.md).

## Troubleshooting

- **`warden binary not found` / MCP client can't launch it.** The SDK resolves
  the binary via `WARDEN_BIN`, then `PATH`. Either `export PATH="$PWD/target/release:$PATH"`,
  set `WARDEN_BIN=/abs/path/to/warden`, or pass `ProxyConfig(..., warden_bin=...)`.
  Because the MCP client launches `warden` as a subprocess, a bare name that
  isn't on the child process's `PATH` fails silently as a spawn error — prefer an
  absolute path when in doubt.

- **`no tools discovered` / client hangs on `get_tools()`.** Warden launches the
  upstream from its own working directory. Run the agent from
  `examples/langgraph` so `python3 tools_server.py` resolves, or make `--upstream`
  an absolute command. Confirm the upstream speaks MCP stdio on its own first:
  `python3 tools_server.py`.

- **Every call denied with an identity error.** With `require_identity = true`
  the proxy fails closed unless a verified token is attached. Ensure `token=`,
  `audience=`, and the verifier (`--token-key` for dev, `--jwks-url`/`--aud` for
  prod) are all set, and that `warden token verify` succeeds standalone.

- **`actor mismatch` / token rejected.** Warden requires the token's **leaf
  actor** (the deepest `sub` in the `act` chain) to equal the proxy's `--agent`.
  If you mint with `TokenBuilder(..., agent="demo-agent")` you must run the proxy
  with `agent="demo-agent"`. Intermediate hops (service principal, assumed role)
  go through `.via(...)`; the leaf is always the wire identity.

- **`--token` and `--request-identity` conflict.** They are mutually exclusive:
  `--token` pins one session principal for every call (sidecar); `--request-identity`
  takes per-request identity (shared gateway). Use one.

## See also

- [The integration model](../integrating/model.md) — orchestration shim ×
  identity adapter.
- [The Python SDK](../integrating/sdk.md) — `ProxyConfig`, `TokenBuilder`, and
  the orchestration helpers.
- [Deployment patterns](../integrating/deployment.md) — sidecar vs shared
  gateway.
- [Configuration (12-factor)](../integrating/configuration.md) — `WARDEN_*` env.
- [The identity token](../concepts/identity-token.md) and
  [policy reference](../reference/policy.md) and
  [CLI reference](../reference/cli.md).
- Identity adapters for the cloud you run on:
  [AWS Bedrock](./aws-bedrock.md),
  [Databricks](./databricks.md),
  [Google ADK / Vertex AI](./google-adk.md),
  [Azure AI Foundry](./azure-ai.md).
- The runnable example:
  [`examples/langgraph`](https://github.com/vijayvedula/warden/tree/main/examples/langgraph).
