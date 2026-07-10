# Google ADK / Vertex AI Agent Engine + Warden

Adopting Warden on Google Cloud: Warden sits as the **MCP proxy** between an
Agent Development Kit (ADK) / Agent Engine agent and its tool servers, and
alongside the **A2A** path for inter-agent calls. Every `tools/call` is checked
against policy (allow / deny / require-approval) and written to a tamper-evident
audit chain.

```
ADK agent --(MCP, stdio)--> Warden --(MCP, stdio subprocess)--> tools_server.py
   |  A2A hops extend act    | verify / policy / hold / audit
   +------------------------>  each call tied to a named IAM principal
```

## Where identity comes from (Google mints it, Warden governs it)

Google IAM issues the credential; Warden does not invent authority, it maps and
enforces what IAM already asserts:

| Google source | Warden claim |
| --- | --- |
| OIDC `sub` / domain-wide-delegation subject | `sub` -- the **accountable human** |
| Service account (workload identity) | `act` -- the acting chain; its **leaf** is the agent's wire identity |
| IAM role bindings (`roles/bigquery.dataViewer`) | `roles` (RBAC) |
| IAM **conditions** (`resource.type == bigquery`) | `attrs` (ABAC) |
| Agent-card A2A capabilities | `scope` (grant) |
| Resource-level IAM bindings | `rel` (ReBAC tuples) |
| Each A2A hop to another agent | one more `act` entry |

On top of IAM, Warden adds two things IAM does not: a **human pre-authorization
hold** (`require_approval`) and a **tamper-evident per-action record** that ties
each executed call to a named IAM principal.

## Wire the ADK MCP toolset through Warden

The only integration change: the agent's MCP toolset launches `warden proxy ...`
instead of the tool server. Use the `google_adk` shim to build the stdio params.

```python
from google.adk.tools.mcp_tool.mcp_toolset import MCPToolset, StdioServerParameters
from warden_sdk import ProxyConfig
from warden_sdk.orchestration import google_adk as wg

cfg = ProxyConfig(
    upstream="python3 tools_server.py",
    agent="prod-agent",
    token=".warden/token.json",
    audience="warden:google",
)
params = wg.warden_connection_params(cfg)   # -> {"command": ..., "args": [...]}
toolset = MCPToolset(connection_params=StdioServerParameters(**params))
```

No other agent code is Warden-aware.

## Three steps

### 1. Mint the identity token

```sh
python mint_token.py alice@example.com
```

This maps a sample workload-identity context (service account + IAM roles /
conditions / resource bindings + agent-card capabilities) into a Warden token
and writes `.warden/token.json`. Verify it:

```sh
warden token verify --token .warden/token.json \
    --agent prod-agent --aud warden:google --token-key dev-secret
```

### 2. Run the proxy in front of your tools

The ADK toolset above launches Warden for you. To run it by hand against the
policy in this directory:

```sh
warden proxy --upstream "python3 tools_server.py" --agent prod-agent \
    --policy warden.policy.toml --token .warden/token.json --aud warden:google \
    --audit .warden/audit.jsonl --approvals .warden/approvals.json
```

With `require_identity = true`, reads pass for the `roles/bigquery.dataViewer`
role, `query_dataset` passes only when the token holds a `dataViewer`
relationship to the exact dataset it targets (ReBAC), and any `delete_*` is
denied before it reaches the tool.

### 3. Verify the audit trail

```sh
warden audit tail   --audit .warden/audit.jsonl   # what ran, what was blocked
warden audit verify --audit .warden/audit.jsonl   # prove the chain is untampered
```

## Production identity (real signed JWTs)

The dev envelope above is for offline runs. In production, don't
`write_dev_envelope`; sign a real JWT via Google IAM / your IdP and have the
proxy verify it against your JWKS:

```python
from warden_sdk import JwtSigner
jwt = tok.to_jwt(JwtSigner.from_file("issuer.pem", "ES256", "k1"), at_jwt=True)
```

```sh
warden proxy ... --jwks-url https://your-idp/.well-known/jwks.json --aud warden:google
```

Adapters never sign authority themselves -- they shape claims; the platform
issuer signs.

## See also

- [../../docs/platform-integration.md](../../docs/platform-integration.md) (Sec 4 -- Google / Vertex / A2A)
- [../../sdk/python/](../../sdk/python/) -- the `warden_sdk` package (google adapter + `google_adk` shim)
