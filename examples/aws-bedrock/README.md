# AWS Bedrock AgentCore + Warden -- adoption example

If you already run agents on **AWS Bedrock AgentCore**, you have two of the three
pieces Warden expects:

- **AgentCore Gateway** turns your APIs / Lambdas into **MCP tools**.
- **AgentCore Identity** handles agent identity, OAuth, and the token vault.

Warden inserts as the **policy + accountability layer on the MCP path** -- between
the agent runtime and the Gateway (or in front of the Gateway's MCP endpoint). It
is a **brake + black-box recorder on the action path, not a Gateway replacement**:
AgentCore exposes tools and IAM controls access; Warden adds the synchronous
human-pre-authorization hold, per-run budgets, and a tamper-evident, hash-chained
audit trail with the full delegation chain folded into each record.

```
Bedrock agent --(MCP)--> Warden --(MCP)--> AgentCore Gateway (APIs / Lambdas as tools)
                          | verify identity / policy / hold / audit
```

## The identity mapping (STS = the delegation)

AWS already carries the delegation you need; Warden just reads it off the STS
`AssumeRole` session that AgentCore Identity gives the agent:

| AWS concept | Warden claim | Meaning |
| --- | --- | --- |
| accountable human behind the role chain | `sub` | who is answerable |
| STS `AssumeRole` **session** (`RoleSessionName`) | middle `act` hop | the delegation; leaf of `act` = the agent |
| STS **session tags** (native ABAC) | `attrs` (`subject:*` conditions) | attributes to gate on |
| assumed **IAM role** | `roles` (RBAC) | role-based allow |
| AssumeRole **session policy** (the narrowing) | `scope` | the agent's delegated grant |

The adapter only *shapes* these claims -- it never signs authority. In production
the token is signed by AgentCore Identity / your IdP; the example signs a local
dev envelope so it runs offline. See
[`../../docs/platform-integration.md`](../../docs/platform-integration.md) (Sec 5)
and the SDK in [`../../sdk/python/`](../../sdk/python/).

## Prerequisites

```sh
# Build (or install) Warden
cargo build --release          # from the repo root -> target/release/warden
export PATH="$PWD/target/release:$PATH"

# Install the SDK (provides the aws identity adapter)
pip install -e sdk/python
```

## 1. Mint the token

`mint_token.py` maps a realistic STS AssumeRole context through the aws adapter
and writes a dev envelope to `.warden/token.json`.

```sh
cd examples/aws-bedrock
python mint_token.py                    # or: python mint_token.py you@example.com
warden token verify --token .warden/token.json \
  --agent prod-agent --aud warden:aws --token-key dev-secret   # -> "token OK"
```

## 2. Run the proxy

Point Warden's upstream at your MCP tool server or the AgentCore Gateway MCP
endpoint, and launch the agent's MCP client against `warden proxy ...` instead:

```python
from warden_sdk import ProxyConfig
cfg = ProxyConfig(
    upstream="python3 tools_server.py",   # or the AgentCore Gateway MCP endpoint
    agent="prod-agent",
    token=".warden/token.json",
    audience="warden:aws",
)
```

Every `tools/call` is now gated by [`warden.policy.toml`](warden.policy.toml):
reads are allowed for the analyst IAM role, `wire_funds` over $1000 **holds** for
human approval, and an ABAC rule keyed on the `team` session tag
(`subject:team == research`) permits reads. Deny by default.

## 3. Verify the audit

```sh
warden audit tail   --audit .warden/audit.jsonl   # what ran, what was held, what was blocked
warden audit verify --audit .warden/audit.jsonl   # prove the record is untampered
```

## Production (don't sign in the adapter)

Adapters shape claims; the platform issuer signs. Instead of the dev envelope,
have AgentCore Identity / your IdP issue a real JWT and let Warden verify it:

```python
from warden_sdk import JwtSigner
tok.to_jwt(JwtSigner.from_file("issuer.pem", "ES256", "k1"), at_jwt=True)
```

Then run the proxy with `--jwks-url <issuer JWKS>` and `--aud warden:aws` so every
action ties to a verified, named human -- with `require_identity = true` in the
policy enforcing it.
