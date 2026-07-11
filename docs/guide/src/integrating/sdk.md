# The Python SDK

`warden-sdk` is the convenience layer for producing Warden tokens and wiring the
proxy into an agent framework. The core is pure-stdlib; JWT signing is an
optional extra.

```sh
pip install warden-sdk             # token builder + adapters + conformance kit
pip install "warden-sdk[jwt]"      # + asymmetric JWT signing (PyJWT)
```

> The proxy always accepts a raw conforming token — the SDK is convenience, not a
> new trust surface (see the [no-forged-authority rule](./model.md)).

## Build a token

```python
from warden_sdk import TokenBuilder

tok = (
    TokenBuilder(sub="alice@example.com", agent="prod-agent")
    .via("svc-principal")                 # act chain: alice -> svc -> agent
    .role("analyst")
    .attr("region", "EU")
    .relation("can_read", "table:sales")  # ReBAC
    .grant("query_table")                 # the agent's delegated scope
    .audience("warden:prod")
    .expires_in(300)
)

# Local/dev: a keyed dev envelope (verified with `--token-key`)
tok.write_dev_envelope(".warden/token.json", key="dev-secret")
```

## Sign a production JWT

```python
from warden_sdk import JwtSigner

signer = JwtSigner.from_file("issuer_ec_priv.pem", alg="ES256", default_kid="k1")
jwt = tok.to_jwt(signer, at_jwt=True)     # RFC 9068 access token
```

Warden accepts only asymmetric algorithms (ES/RS/PS/EdDSA), blocking the
RS256→HS256 confusion downgrade. In production the private key should live in a
KMS/HSM and the *platform issuer* should sign; `JwtSigner` is the local/dev
signer.

## Identity adapters

Map a platform's native identity to canonical claims — pure data mapping.

```python
from warden_sdk.adapters import aws, databricks, google, azure

tok = aws.from_sts_session({
    "accountable": "alice@example.com",
    "session_name": "agent-session",
    "session_tags": {"team": "research"},     # -> ABAC attrs
    "iam_roles": ["arn:aws:iam::…:role/analyst"],
    "session_policy_actions": ["query_table"],
}, agent="prod-agent", audience="warden:prod")
```

| Adapter | Entry point | Native source |
|---------|-------------|---------------|
| `aws` | `from_sts_session` | STS AssumeRole + session tags (Bedrock AgentCore) |
| `databricks` | `from_obo` | on-behalf-of-user + Unity Catalog grants |
| `google` | `from_workload_identity` | workload identity / service account (Vertex ADK / A2A) |
| `azure` | `from_entra_obo` | Entra ID managed identity + OBO |

## Orchestration shims

Point a framework's MCP client at `warden proxy` — no other agent code changes.

```python
from warden_sdk import ProxyConfig
from warden_sdk.orchestration import langgraph as wl

cfg = ProxyConfig(upstream="python3 tools_server.py", agent="prod-agent",
                  token=".warden/token.json", audience="warden:prod")
servers = wl.warden_mcp_servers(cfg)          # for MultiServerMCPClient
```

`warden_sdk.orchestration.google_adk.warden_connection_params(cfg)` gives the
equivalent stdio params for the Google ADK MCP toolset. `ProxyConfig.command()`
returns the full `warden proxy …` argv for any launcher.

## Conformance kit

A token is conformant iff it passes `warden token verify` — the exact check the
proxy runs. The kit shells out to the real binary, so first-party *and* community
adapters are verifiable against ground truth:

```python
from warden_sdk import TokenBuilder, verify_token

env = TokenBuilder(sub="alice", agent="prod-agent").audience("warden:prod") \
    .dev_envelope(key="dev-secret")
verify_token(env, agent="prod-agent", audience="warden:prod",
             token_key="dev-secret").raise_for_status()
```

Now pick your [provider guide](../providers/index.md) for the full walkthrough.
