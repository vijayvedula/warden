# LangGraph + Warden -- runnable example (on-prem / local)

A LangGraph ReAct agent whose tool calls are governed by Warden. The agent
reads a table (**allowed**), then tries to drop a database (**blocked by
Warden** before it reaches the tool). Everything is recorded in a tamper-evident
audit trail.

```
LangGraph agent --(MCP, stdio)--> Warden --(MCP, stdio subprocess)--> tools_server.py
                                    | verify / policy / hold / audit
```

The only integration change: the agent's MCP client launches **`warden proxy ...`**
instead of the tool server. No other agent code is Warden-aware.

## Prerequisites

```sh
# 1. Build (or install) Warden
cargo build --release          # from the repo root -> target/release/warden
export PATH="$PWD/target/release:$PATH"

# 2. Python deps for the agent + tool server
pip install langgraph langchain-mcp-adapters langchain-anthropic mcp

# 3. The agent's model key
export ANTHROPIC_API_KEY=sk-ant-...
```

## Run

```sh
cd examples/langgraph
python3 agent.py
```

You'll see the agent read the table successfully, then receive a clean tool
error -- `BLOCKED by Warden: destructive: agents may not drop databases` -- for
the delete. Then inspect what it was allowed to do:

```sh
warden audit tail   --audit .warden/audit.jsonl   # read_records=executed, delete_database=blocked
warden audit verify --audit .warden/audit.jsonl   # prove the record is untampered
```

## Try the human-in-the-loop path

Point the agent at `create_ticket` (policy = `require_approval`). The call will
**hold**; from another terminal release it:

```sh
warden approvals list --approvals .warden/approvals.json
warden approve <id> --by you --approvals .warden/approvals.json
```

## Make it production-grade (uncomment in `agent.py`)

- **Accountability:** `require_identity = true` in the policy + launch Warden with
  a verified token (`--jwks-url`/`--aud`) so every action ties to a named human.
- **Evidence:** add `--anchor`/`--anchor-key` (rollback-proof) and `--ocsf` (SIEM).
- **Authorization:** add RBAC/ABAC/ReBAC rules (see the policy file).

See [docs/integrations/langgraph.md](../../docs/integrations/langgraph.md) for the
AWS variant (Bedrock model + Cognito/STS identity + HTTP gateway) and
[docs/deployment.md](../../docs/deployment.md) for deploying Warden anywhere.
