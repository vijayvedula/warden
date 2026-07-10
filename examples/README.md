# Warden examples — how teams adopt

Each example shows the **same adoption pattern** on a different stack: point your
agent's MCP client at `warden proxy` instead of the tool server, mint a signed
delegation token that says *who the agent acts for*, and enforce policy on every
tool call — with a tamper-evident audit trail.

```
agent framework --(MCP)--> warden proxy --(MCP)--> your tool server
                              |  verify token · policy · hold · audit
```

| Example | Orchestration | Identity source | Runnable offline? |
|---------|---------------|-----------------|-------------------|
| [langgraph/](langgraph/) | LangGraph ReAct agent | dev token (or any cloud) | ✅ full end-to-end |
| [databricks/](databricks/) | Mosaic AI Agent Framework | on-behalf-of-user + Unity Catalog | token + policy; live run needs Databricks |
| [aws-bedrock/](aws-bedrock/) | Bedrock AgentCore | STS AssumeRole + session tags | token + policy; live run needs AWS |
| [google-adk/](google-adk/) | Google ADK / Vertex Agent Engine | workload identity / service account | token + policy; live run needs GCP |
| [azure-ai/](azure-ai/) | Azure AI Foundry Agent Service | Entra ID managed identity + OBO | token + policy; live run needs Azure |

Every example uses the **[warden-sdk](../sdk/python/)** identity adapters to mint
the token and the orchestration shims to wire the proxy. The proxy always accepts
a raw conforming token with no SDK at all — the SDK is convenience.

## The three steps every example follows

1. **Mint** a token from your platform identity → `python mint_token.py`
   (uses `warden_sdk.adapters.<platform>`).
2. **Run** the agent through `warden proxy --token .warden/token.json
   --policy warden.policy.toml` (the SDK's `ProxyConfig` builds the command).
3. **Verify** what the agent did → `warden audit tail` and `warden audit verify`.

## Start here

New to Warden? Run the fully self-contained walkthrough first — no API key, no
cloud:

```sh
cargo build
./target/debug/warden demo
./target/debug/warden audit verify --audit .warden-demo/audit.jsonl
```

Then work through [langgraph/](langgraph/) for a real (local) agent, and the
cloud examples for the identity wiring on your platform.
