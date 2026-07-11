# AWS Bedrock (AgentCore)

If you already run agents on **AWS Bedrock AgentCore**, you have two of the three
pieces Warden expects, and the third is a thin adapter you drop in on the agent
side. This chapter shows how to place Warden on the MCP action path, mint a
Warden token from an STS `AssumeRole` session, write an AWS-appropriate policy,
and prove the audit chain.

> The identity adapter (`warden_sdk.adapters.aws`) only *shapes* claims; it never
> signs authority. In production your platform issuer (AgentCore Identity / your
> IdP) signs the token and Warden verifies it. See
> [The identity token](../concepts/identity-token.md) and
> [The Python SDK](../integrating/sdk.md).

## Overview

AgentCore already covers tool exposure and identity:

- **AgentCore Gateway** turns your APIs / Lambdas into **MCP tools**.
- **AgentCore Identity** handles agent identity, OAuth, and the token vault.

Warden is the **policy + accountability layer on the MCP path** — the synchronous
human-pre-authorization hold, per-run budgets, and a tamper-evident, hash-chained
audit trail with the full delegation chain folded into each record. It inserts
between the agent runtime and the Gateway (or in front of the Gateway's MCP
endpoint). It is a **brake + black-box recorder on the action path, not a Gateway
replacement**: AgentCore exposes tools and IAM controls access; Warden adds the
"could the accountable human have known/authorized this, and can we prove it"
property.

```
agent runtime --(MCP)--> warden proxy --(MCP)--> AgentCore Gateway / MCP tools
                          |
                          | verify identity  ->  policy (allow / deny / hold)
                          | pre-auth hold    ->  per-run budget
                          | hash-chained audit (delegation chain folded in)
```

Nothing about the Gateway changes. You point Warden's upstream at your existing
MCP tool server or the Gateway's MCP endpoint, and launch the agent's MCP client
against `warden proxy ...` instead.

## Identity mapping

AWS already carries the delegation you need. Warden reads it off the STS
`AssumeRole` session that AgentCore Identity gives the agent — no new identity
system, just a claims mapping.

| Warden claim | AWS source | Meaning |
| --- | --- | --- |
| `sub` | accountable human behind the role chain | who is answerable |
| `act` (middle hop) | STS `AssumeRole` **session** (`RoleSessionName`) | the delegation; the **leaf** of `act` is the agent's wire identity |
| `roles` (RBAC) | assumed **IAM role(s)** | role-based allow |
| `attrs` (ABAC) | STS **session tags** (native ABAC) | attributes to gate on, addressable as `subject:*` |
| `scope` (grant) | AssumeRole **session policy** (the narrowing) | the agent's delegated grant |
| `rel` / `resource_attrs` | **resource tags** on what the tools touch | relationship / resource attributes for policy |

The leaf of the `act` chain must equal the `--agent` the proxy runs as; that is
the invariant the token verifier checks. Everything else is
trusted-because-signed and consumed by the policy engine.

## Prerequisites

```sh
# Build (or install) Warden — from the repo root -> target/release/warden
cargo build --release
export PATH="$PWD/target/release:$PATH"

# Install the SDK (provides the aws identity adapter). Add the [jwt] extra for
# the production signing path in Step 1.
pip install "warden-agent-sdk[jwt]"
```

You also need an AWS environment where AgentCore Identity (or your IdP) performs
the STS `AssumeRole` that gives the agent its session — that session is what you
decode into the adapter context below.

## Step 1 — Mint a Warden token from the STS session

The adapter entry point is `warden_sdk.adapters.aws.from_sts_session`:

```python
from warden_sdk.adapters import aws

def from_sts_session(
    context: dict,
    *,
    agent: str,
    audience: str | None = None,
    ttl_seconds: int = 300,
) -> TokenBuilder: ...
```

`context` is a **decoded STS `AssumeRole` context**. In production these values
are not hand-written — they come from the session AgentCore Identity hands the
agent. The keys (all optional except `accountable`):

| Context key | Type | Maps to |
| --- | --- | --- |
| `accountable` (**required**) | `str` | `sub` — the human behind the role chain |
| `session_name` | `str` | middle `act` hop (STS `RoleSessionName`) |
| `session_tags` | `dict` | `attrs` (ABAC), addressable as `subject:<tag>` |
| `iam_roles` | `list[str]` | `roles` (RBAC) |
| `session_policy_actions` | `list[str]` | `scope` (the grant) |
| `resource_tags` | `dict[str, dict]` | `resource_attrs` (per-resource attributes) |

A realistic mapping:

```python
from warden_sdk.adapters import aws

AGENT = "prod-agent"
AUDIENCE = "warden:aws"

# The decoded STS AssumeRole session AgentCore Identity handed the agent.
sts_context = {
    "accountable": "alice@example.com",              # -> sub
    "session_name": "agent-session-123",             # -> middle act hop
    "session_tags": {"team": "research"},            # -> attrs (subject:team)
    "iam_roles": ["arn:aws:iam::111122223333:role/analyst"],  # -> roles
    "session_policy_actions": ["query_table"],       # -> scope
    "resource_tags": {"table:sales": {"classification": "public"}},  # -> resource_attrs
}

tok = aws.from_sts_session(sts_context, agent=AGENT, audience=AUDIENCE)
```

`from_sts_session` returns a `TokenBuilder`. You then emit a token in one of two
ways.

### Local / dev — a dev envelope

For offline development the SDK writes an HMAC-signed **dev envelope** whose
signature verifies under `--token-key`. This is a development/test convenience,
**not an enforcement mode**.

```python
from pathlib import Path

Path(".warden").mkdir(parents=True, exist_ok=True)
tok.write_dev_envelope(".warden/token.json", key="dev-secret")
```

Verify it exactly as the proxy will:

```sh
warden token verify --token .warden/token.json \
  --agent prod-agent --aud warden:aws --token-key dev-secret
# -> "token OK"  (and prints the decoded delegation chain)
```

### Production — the platform issuer signs

**Do not sign in the adapter.** The adapter shapes claims; the platform issuer
signs. Have AgentCore Identity / your IdP issue a real JWT (Warden accepts only
asymmetric algorithms — `RS*`/`PS*`/`ES*`/`EdDSA` — which blocks the
`RS256`→`HS256` confusion downgrade). The `JwtSigner` below is the local/dev
signer; in production the private key lives in KMS/HSM and the issuer signs:

```python
from warden_sdk import JwtSigner

# Key from KMS/HSM in production; issuer.pem here is illustrative.
signer = JwtSigner.from_file("issuer.pem", "ES256", default_kid="k1")

# at_jwt=True stamps RFC 9068 typ=at+jwt so --require-at-jwt accepts it.
jwt = tok.to_jwt(signer, at_jwt=True)
```

Then run the proxy against the issuer's JWKS and expected audience so every
action ties to a verified, named human:

```sh
warden token verify --token token.jwt \
  --agent prod-agent --aud warden:aws --jwks-url https://issuer.example/.well-known/jwks.json
```

The **no-forged-authority rule**: an adapter is untrusted client code — it runs
on the side Warden exists to police. It orchestrates the platform's native token
exchange and shapes claims; the trusted signer stays the platform issuer (STS /
AgentCore Identity / your IdP). An adapter that held its own broad-scope signing
key would become a single high-value secret and collapse the accountability
model. See the [SDK chapter](../integrating/sdk.md).

## Step 2 — Route tool calls through Warden

The only integration change the agent framework needs is to launch
`warden proxy ...` instead of its tool server. `ProxyConfig` builds that
invocation and the MCP client stanza:

```python
from warden_sdk import ProxyConfig

cfg = ProxyConfig(
    upstream="python3 tools_server.py",   # or the AgentCore Gateway MCP endpoint
    agent="prod-agent",
    policy="warden.policy.toml",
    token=".warden/token.json",           # dev envelope; or the JWT from Step 1
    audience="warden:aws",
    audit=".warden/audit.jsonl",
    approvals=".warden/approvals.json",
)

# Hand this stanza to langchain_mcp_adapters / MultiServerMCPClient, etc.
mcp_server = cfg.mcp_stdio_config()
# {"command": "...warden", "args": ["proxy", "--upstream", ...], "transport": "stdio"}
```

For the **production** JWT path, drop the local `token=` and verify against the
issuer instead:

```python
cfg = ProxyConfig(
    upstream="python3 tools_server.py",
    agent="prod-agent",
    audience="warden:aws",
    jwks_url="https://issuer.example/.well-known/jwks.json",
    issuer="https://issuer.example",
)
```

### Shared gateway — per-request bearer

For a **sidecar** (one Warden per agent session) the token above is fixed for the
process. For a **shared gateway** — one Warden HTTP endpoint fronting many agents
— each call must carry its own bearer identity. Set `request_identity=True`
(emits `--request-identity`) so Warden reads the per-request token instead of a
process-wide one:

```python
cfg = ProxyConfig(
    upstream="python3 tools_server.py",
    agent="prod-agent",
    audience="warden:aws",
    jwks_url="https://issuer.example/.well-known/jwks.json",
    request_identity=True,
    extra_args=["--http", "127.0.0.1:8080"],
)
```

Sidecar vs shared gateway is a real trade-off — see
[Deployment patterns](../integrating/deployment.md).

## Step 3 — Write a policy

The policy is evaluated on every `tools/call`. First matching rule wins; else
`default`. Here is the AWS-appropriate `warden.policy.toml`:

```toml
# First matching rule wins; else `default`. Every tools/call is gated here.
default = "deny"

# No action runs without a verified identity (a named human behind the agent).
# The human comes from the STS AssumeRole session -> token `sub`.
require_identity = true

# Reads are allowed for the assumed analyst IAM role. RBAC on `roles`, which the
# adapter fills from the STS-assumed IAM role ARN.
[[rules]]
tool = "read_*"
decision = "allow"
require_role = "arn:aws:iam::111122223333:role/analyst"

# ABAC keyed on an STS session tag. `session_tags = {team = "research"}` maps to
# `attrs`, addressable as `subject:team`. Research-team sessions may read.
[[rules]]
tool = "read_*"
when = { field = "subject:team", op = "eq", value = "research" }
decision = "allow"

# High-value side effects wait for a human. Condition is on a tool argument:
# only funds transfers over $1000 need pre-authorization (warden approve <id>).
[[rules]]
tool = "wire_funds"
when = { arg = "amount", op = "gt", value = 1000 }
decision = "require_approval"
reason = "high-value transfer requires human pre-authorization"

# Destructive operations are never allowed for this agent.
[[rules]]
tool = "delete_*"
decision = "deny"
reason = "destructive operations are out of scope for the analyst agent"
```

Notes on the AWS mappings above:

- `require_role` matches against `roles`, which the adapter fills from
  `iam_roles` (the assumed IAM role ARN).
- `field = "subject:team"` reads the `team` **STS session tag** carried in
  `attrs` — native ABAC, no separate attribute store.
- `arg = "amount"` inspects the tool call's arguments; the `require_approval`
  decision **holds** the call for a human (Step 4).

Validate before you ship:

```sh
warden policy lint --policy warden.policy.toml   # unreachable rules, bad fields
warden policy show --policy warden.policy.toml   # the loaded, effective policy
```

See the [Policy reference](../reference/policy.md) for the full rule grammar.

## Step 4 — Run & verify

Launch the proxy (the framework does this via `cfg.command()`; the raw form):

```sh
warden proxy \
  --upstream "python3 tools_server.py" \
  --agent prod-agent \
  --policy warden.policy.toml \
  --token .warden/token.json --aud warden:aws --token-key dev-secret \
  --audit .warden/audit.jsonl \
  --approvals .warden/approvals.json \
  --log-format json
```

Now every `tools/call` is gated: reads are allowed for the analyst IAM role,
`wire_funds` over $1000 **holds** for approval, research-team sessions may read,
`delete_*` is denied, and everything else is denied by default.

When a call is held, approve or deny it out of band:

```sh
warden approvals list                 # pending held actions
warden approve <id> --by alice@example.com
warden deny    <id> --by alice@example.com
```

Inspect and prove the record:

```sh
warden audit tail   --audit .warden/audit.jsonl   # what ran / held / blocked
warden audit verify --audit .warden/audit.jsonl   # prove the chain is untampered
```

`audit verify` recomputes the hash chain — with the full delegation chain
(`sub` + `act`) folded into each record — and fails loudly on any tampering. See
[The audit chain](../concepts/audit.md).

## Production notes

- **Sender-constrain the HTTP surface.** When you expose Warden over `--http`
  (shared gateway), bind tokens to a DPoP proof key so a stolen bearer is
  unusable off-host. The token builder carries the binding via
  `TokenBuilder.dpop_jkt(...)` (RFC 7800 `cnf.jkt`); pair it with per-request
  bearers (`--request-identity`).
- **Anchor evidence externally.** Add `--anchor <file> --anchor-key <pem>` to the
  proxy to emit signed checkpoints, and ship them to WORM storage / your SIEM;
  verify with `warden audit verify --anchor <file> --anchor-pub <pem>`. This is
  what makes the black-box recorder defensible under audit.
- **Sidecar vs shared gateway.** Prefer a **sidecar** (one Warden per agent
  runtime/session) — it keeps revocation surgical (pause → reload one process).
  A **shared gateway** is simpler to operate but forfeits surgical revocation and
  concentrates the trust boundary. See
  [Deployment patterns](../integrating/deployment.md).
- **12-factor config.** Every flag has a `WARDEN_*` environment-variable and
  `[proxy]` TOML-table equivalent; flags override the config file. Keep secrets
  and endpoints out of the command line in production. See
  [Configuration (12-factor)](../integrating/configuration.md).
- **Keep signing keys in KMS.** The issuer's private key (AgentCore Identity /
  your IdP) belongs in KMS/HSM — never in the adapter, never on the agent host.
  Warden only ever holds the **public** JWKS.

## Troubleshooting

- **`leaf actor != --agent`.** The deepest `sub` in the token's `act` chain must
  equal the `--agent` the proxy runs as. If you mint with `agent="prod-agent"`,
  run the proxy with `--agent prod-agent`. The middle `act` hop
  (`session_name`) is fine; it is the leaf that must match.
- **Missing / mismatched `aud`.** If you set `audience=` when minting, you must
  pass the same `--aud` to `warden proxy` / `warden token verify`, or
  verification rejects the token. Omit it in both places, or set it in both.
- **Per-request bearer vs session token.** On a shared HTTP gateway a
  process-wide `--token` will not reflect the caller. Use `--request-identity`
  and have each call carry its own bearer; on a sidecar, the fixed `--token` is
  correct.
- **`algorithm ... is not asymmetric`.** `JwtSigner` (and the verifier) reject
  `HS*`. Use `ES256`/`RS256`/`EdDSA` and a matching key type.
- **`require_identity = true` blocks everything.** That is by design when no
  token verifies. Confirm `warden token verify ...` prints `token OK` first, then
  run the proxy with the same `--aud` and key/JWKS flags.

## See also

- Example sources: [`examples/aws-bedrock`](https://github.com/vijayvedula/warden/tree/main/examples/aws-bedrock)
  (`README.md`, `mint_token.py`, `warden.policy.toml`).
- [The Python SDK](../integrating/sdk.md) — adapters, `ProxyConfig`, signing.
- [Deployment patterns](../integrating/deployment.md) — sidecar vs shared gateway.
- [Configuration (12-factor)](../integrating/configuration.md) — `WARDEN_*` env.
- [Policy reference](../reference/policy.md) and [CLI reference](../reference/cli.md).
- [The identity token](../concepts/identity-token.md) — the RFC 8693 claim model.
- Sibling provider guides: [LangGraph](./langgraph.md),
  [Databricks (Mosaic AI)](./databricks.md),
  [Google ADK / Vertex AI](./google-adk.md).
