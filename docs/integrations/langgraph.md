# LangGraph + Warden -- Integration Guide

How to put a **LangGraph** agent behind Warden so every tool call is verified,
policy-checked, optionally held for a human, and recorded -- first **on-prem**,
then on **AWS**. A runnable on-prem example lives in
[`examples/langgraph/`](../../examples/langgraph/).

## The one idea

LangGraph agents call **MCP tools** (via `langchain-mcp-adapters`). To govern
them, point the MCP client at **Warden** instead of the tool server. Warden
launches the real tool server as its upstream and enforces every `tools/call`.
**No agent logic changes** -- only the MCP client target.

```
LangGraph (create_react_agent)
   \- langchain-mcp-adapters (MCP client)
        \-> Warden  -- verify token / policy (RBAC/ABAC/ReBAC) / hold / audit / revoke
              \-> tool MCP server (DB / tickets / internal APIs)
```

---

## Scenario A -- On-prem (Warden sidecar, stdio)

The cleanest model: one Warden **per agent**, co-located, over stdio. The agent
gets per-agent identity and surgical revocation. This is the runnable example.

**Integration is one block** -- the MCP client launches `warden proxy ...`:

```python
from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain_anthropic import ChatAnthropic
from langgraph.prebuilt import create_react_agent

client = MultiServerMCPClient({
    "tools": {
        "command": "warden",                       # <- Warden, not the tool server
        "args": [
            "proxy", "--upstream", "python3 tools_server.py",
            "--agent", "demo-agent", "--policy", "warden.policy.toml",
            "--audit", ".warden/audit.jsonl",
        ],
        "transport": "stdio",
    }
})
tools = await client.get_tools()                   # discovered THROUGH Warden
agent = create_react_agent(ChatAnthropic(model="claude-sonnet-4-6"), tools)
await agent.ainvoke({"messages": [("user", "Read customers; then drop prod db.")]})
```

The agent reads (**allowed**) and the destructive delete comes back as a clean
tool error (**blocked by Warden**) -- both in the audit trail. Run it:

```sh
cd examples/langgraph && python3 agent.py
warden audit tail --audit .warden/audit.jsonl
```

**Make it production-grade (on-prem):**

```toml
# warden.proxy.toml
[proxy]
upstream = "python3 tools_server.py"
agent = "demo-agent"
policy = "warden.policy.toml"
jwks-url = "https://idp.internal/.well-known/jwks.json"   # verify real tokens
aud = "warden:prod"
require-at-jwt = true
anchor = ".warden/anchor.jsonl"                            # rollback-proof evidence
anchor-key = "/keys/anchor.pem"
ocsf = ".warden/ocsf.jsonl"                                # -> your SIEM
redact = "gdpr,pci,secrets"                                # scrub recorded PII

[[sink]]                                                   # -> SIEM, off the hot path
name = "siem"; format = "ocsf"; transport = "webhook"
endpoint = "https://collector.internal/ocsf"; delivery = "fail-safe"
```

...and turn on accountability in the policy (`require_identity = true` + RBAC/ABAC/
ReBAC). Now every action ties to a named human behind the agent.

---

## Scenario B -- AWS (LangGraph on EKS, Bedrock model, AWS-native identity & evidence)

Same agent, three AWS-native swaps: **model**, **identity**, **evidence**.

### 1. Model -> Amazon Bedrock

```python
from langchain_aws import ChatBedrock                      # pip install langchain-aws
model = ChatBedrock(model="anthropic.claude-3-5-sonnet-20240620-v1:0",
                    region_name="us-east-1")
agent = create_react_agent(model, tools)                   # tools unchanged
```

### 2. Identity -> carried from AWS, verified by Warden

In EKS, the pod already has a **projected OIDC service-account token** (a JWT
signed by the cluster's OIDC provider). Use it (or a Cognito user token for
human-on-behalf-of) as Warden's session token; Warden verifies via OIDC
discovery -- no identity re-platforming:

```toml
[proxy]
token = "/var/run/secrets/warden/token"                    # projected OIDC / Cognito JWT
issuer-url = "https://oidc.eks.us-east-1.amazonaws.com/id/XXXX"   # -> JWKS via discovery
aud = "warden:prod"
require-at-jwt = true
```

(For human accountability, an **adapter** mints an RFC-8693 token --
`sub` = human, `act` = service -> agent -- from Cognito/STS; Warden verifies and
records the chain.)

### 3. Evidence & control -> AWS-native sinks

```toml
[[sink]]                                   # decisions -> Amazon Security Lake (OCSF-native)
name = "security-lake"; format = "ocsf"; transport = "webhook"
endpoint = "https://<collector>/ocsf"; delivery = "fail-safe"

[[sink]]                                   # signed signals -> your IdP / SSF
name = "ssf"; format = "caep"; transport = "webhook"
endpoint = "https://idp/ssf/events"; key = "/keys/set.pem"; filter = "high-risk"
```

- Audit + anchor -> **S3 with Object Lock** (WORM); schedule `warden audit verify`.
- Signing keys -> **KMS / Secrets Manager** (CSI driver), mounted read-only.
- Revocation feed -> shared location; `warden revoke --jti ...` cuts an agent live.

### 4. Deploy (EKS sidecar)

Agent + Warden in one pod (see [deployment.md Sec 3c/Sec 4b](../deployment.md)); the
agent reaches Warden on `127.0.0.1:8080`, tools only through Warden:

```python
# AWS: agent -> Warden over loopback HTTP (gateway in the sidecar)
client = MultiServerMCPClient({
    "tools": {
        "transport": "streamable_http",
        "url": "http://127.0.0.1:8080/",
        "headers": {"Authorization": f"Bearer {os.environ['WARDEN_HTTP_TOKEN']}"},
    }
})
```

```sh
# the Warden sidecar (HTTP), launched from the pod spec
warden proxy --config /cfg/warden.proxy.toml --http 127.0.0.1:8080 \
  --http-auth-token "$WARDEN_HTTP_TOKEN"
```

> **Identity note:** Warden binds **one accountable principal per process**
> (`--token`). For **per-developer/per-agent** accountability, use the
> **sidecar** (one Warden per agent, as above). A **shared HTTP gateway** binds a
> single service principal -- fine for a single-tenant fleet, but use sidecars
> when each action must trace to a different human.

---

## What each persona sees here

- **Developers:** a 6-line change (point the MCP client at `warden`) and a
  runnable example; no agent rewrite.
- **Architects:** clean trust boundary, sidecar vs gateway, AWS-native identity
  (OIDC/IRSA/Cognito) + evidence (Security Lake/S3-WORM/SSF), per-process
  accountability semantics.
- **Security/GRC:** every tool call verified, policy-gated, held when risky,
  recorded tamper-evidently with PII redacted, revocable live.
- **VC:** the same control plane drops under *any* LangGraph deployment, on any
  cloud, with no agent or identity re-platforming -- the neutrality thesis, shown.

## Next
- Run it: [`examples/langgraph/`](../../examples/langgraph/)
- Deploy Warden anywhere: [deployment.md](../deployment.md)
- Trust model & standards: [threat-model.md](../threat-model.md) / [standards.md](../standards.md)
