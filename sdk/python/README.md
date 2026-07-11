# warden-sdk (Python)

Client SDK for [Warden](https://github.com/vijayvedula/warden) — build and sign
canonical Warden **delegation tokens**, and route agent frameworks through the
Warden **MCP proxy**.

Warden's identity boundary is a single signed token that says *who an agent acts
for* (RFC 8693): `sub` is the accountable human, `act` is the nested acting chain
whose leaf is the agent, and `roles`/`attrs`/`rel`/`scope` carry
RBAC/ABAC/ReBAC/grant. This SDK is the convenience layer for producing that token
and wiring it in. **The proxy always accepts a raw conforming token with no SDK
at all** — this package is convenience, not a new trust surface.

## Install

```sh
pip install warden-sdk            # core (pure stdlib): token builder + conformance
pip install "warden-sdk[jwt]"     # + asymmetric JWT signing (PyJWT)
```

## Build a token

```python
from warden_sdk import TokenBuilder

tok = (
    TokenBuilder(sub="alice@example.com", agent="prod-agent")
    .via("svc-principal")                     # act chain: alice -> svc -> agent
    .role("analyst")
    .relation("can_read", "table:sales")      # ReBAC
    .grant("query_table")                     # agent's delegated scope
    .audience("warden:prod")
    .expires_in(300)
)

# Local/dev: a keyed dev envelope (verified with `--token-key`)
tok.write_dev_envelope(".warden/token.json", key="dev-secret")

# Production: a compact JWT signed by an asymmetric key (or your KMS)
from warden_sdk import JwtSigner
signer = JwtSigner.from_file("issuer_ec_priv.pem", alg="ES256", default_kid="k1")
jwt = tok.to_jwt(signer, at_jwt=True)
```

## Identity adapters

Map a platform's native identity to canonical claims. Adapters are pure data
mapping — they never sign authority themselves.

```python
from warden_sdk.adapters import aws, databricks, google, azure

tok = aws.from_sts_session({
    "accountable": "alice@example.com",
    "session_name": "agent-session",
    "session_tags": {"team": "research"},     # STS session tags -> ABAC attrs
    "iam_roles": ["arn:aws:iam::…:role/analyst"],
    "session_policy_actions": ["query_table"],
}, agent="prod-agent", audience="warden:prod")
```

| Adapter | Native source | Entry point |
|---|---|---|
| `aws` | STS AssumeRole session + session tags (Bedrock AgentCore) | `from_sts_session` |
| `databricks` | on-behalf-of-user + Unity Catalog grants | `from_obo` |
| `google` | workload identity / service account (Vertex ADK / A2A) | `from_workload_identity` |
| `azure` | Entra ID managed identity + OBO | `from_entra_obo` |

## Orchestration shims

Point an agent framework's MCP client at `warden proxy` instead of the tool
server — no other agent code changes.

```python
from warden_sdk import ProxyConfig
from warden_sdk.orchestration import langgraph as wl
from langchain_mcp_adapters.client import MultiServerMCPClient

cfg = ProxyConfig(upstream="python3 tools_server.py", agent="prod-agent",
                  token=".warden/token.json", audience="warden:prod")
client = MultiServerMCPClient(wl.warden_mcp_servers(cfg))
tools = await client.get_tools()   # discovered THROUGH Warden
```

`warden_sdk.orchestration.google_adk` provides the equivalent for the Google ADK
MCP toolset.

## Conformance

A token is conformant iff it passes `warden token verify` — the exact check the
proxy runs. The kit shells out to the real binary so first-party and community
adapters are verifiable against ground truth:

```python
from warden_sdk import TokenBuilder, verify_token

env = TokenBuilder(sub="alice", agent="prod-agent").audience("warden:prod") \
    .dev_envelope(key="dev-secret")
verify_token(env, agent="prod-agent", audience="warden:prod",
             token_key="dev-secret").raise_for_status()
```

## Develop

```sh
pip install -e ".[dev]"
cargo build            # from the repo root, so the conformance tests find `warden`
pytest
ruff check .
```

Source-available under the **Functional Source License 1.1 (FSL-1.1-ALv2)** —
free for any use except a Competing Use; each version becomes Apache-2.0 two
years after release. See [LICENSE](../../LICENSE).
