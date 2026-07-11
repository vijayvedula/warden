# Govern your first agent

The only integration change is this: your agent's MCP client launches
**`warden proxy …`** instead of the tool server. No other agent code becomes
Warden-aware. This chapter uses the runnable
[LangGraph example](https://github.com/vijayvedula/warden/tree/main/examples/langgraph);
the same shape applies to any MCP-speaking framework.

## Before and after

```text
# Before: the agent's MCP client launches the tool server directly
tools_server  <----(MCP)----  agent

# After: it launches Warden, which launches the tool server
tools_server  <--(MCP)--  warden proxy  <--(MCP)--  agent
```

## Point the client at Warden

With the SDK's `ProxyConfig` (Python):

```python
from warden_sdk import ProxyConfig
from warden_sdk.orchestration import langgraph as wl
from langchain_mcp_adapters.client import MultiServerMCPClient

cfg = ProxyConfig(
    upstream="python3 tools_server.py",   # your real MCP tool server
    agent="prod-agent",
    policy="warden.policy.toml",
)
client = MultiServerMCPClient(wl.warden_mcp_servers(cfg))
tools = await client.get_tools()          # discovered THROUGH Warden
```

Or the raw command, for any client that launches an MCP stdio server:

```sh
warden proxy --upstream "python3 tools_server.py" \
  --agent prod-agent --policy warden.policy.toml \
  --audit .warden/audit.jsonl --approvals .warden/approvals.json --log-format json
```

## Watch it govern

Give the agent a task that mixes a safe and an unsafe action ("read the customers
table, then drop the prod database"). You'll see the read **allowed** and the
drop returned to the agent as a clean tool error —
`BLOCKED by Warden: …` — before it ever reaches the tool. Then:

```sh
warden audit tail --audit .warden/audit.jsonl     # read=executed, delete=blocked
```

## Add accountability

So far this is audit + policy with no identity. To tie every action to a named
human, add a verified token and set `require_identity = true` in the policy:

```sh
warden proxy … --token .warden/token.json --aud warden:prod \
  --jwks-url https://your-idp/.well-known/jwks.json
```

Where does the token come from? A platform **identity adapter** mints it — see
your [provider guide](../providers/index.md) and the
[Python SDK](../integrating/sdk.md). For a local dry-run you can mint a dev token
(see [Write a policy](./write-policy.md) and the example's `mint_token.py`).

## Human-in-the-loop

Point a rule at `decision = "require_approval"`. The call **holds**; release it
from another terminal:

```sh
warden approvals list --approvals .warden/approvals.json
warden approve <id> --by you --approvals .warden/approvals.json
```

Next: [Write a policy](./write-policy.md).
