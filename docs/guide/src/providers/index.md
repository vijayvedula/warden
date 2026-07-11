# Choosing your provider guide

Each guide below is a **complete, end-to-end walkthrough** for one Agentic AI
provider: where Warden sits, how that platform's identity maps to Warden's token,
minting the token with the SDK adapter, routing tool calls through the proxy, a
provider-appropriate policy, running it, and verifying the audit.

They all follow the same [integration model](../integrating/model.md) — the token
is the only interface — so once you've done one, the others are familiar.

| Guide | Orchestration | Identity source | Start here if… |
|-------|---------------|-----------------|----------------|
| [**LangGraph**](./langgraph.md) | LangGraph ReAct agent | dev token, or any cloud adapter | you build agents with LangGraph (runs fully locally) |
| [**AWS Bedrock**](./aws-bedrock.md) | Bedrock AgentCore | STS AssumeRole + session tags | your agents run on AgentCore Gateway/Identity |
| [**Databricks**](./databricks.md) | Mosaic AI Agent Framework | on-behalf-of-user + Unity Catalog | your tools are UC functions / Databricks-hosted MCP |
| [**Google ADK**](./google-adk.md) | ADK / Vertex Agent Engine | workload identity / service account | you use ADK or Vertex Agent Engine (or A2A) |
| [**Azure AI Foundry**](./azure-ai.md) | Foundry Agent Service | Entra ID managed identity + OBO | your agents run in Azure AI Foundry |

## Identity vs orchestration

Two of these are **orchestration** frameworks (LangGraph, Google ADK) and the
rest are **identity** platforms — and they compose. LangGraph has no identity
issuer of its own: run it on a cloud and pair its orchestration shim with that
cloud's identity adapter. The [SDK chapter](../integrating/sdk.md) shows both
sides.

## Not listed here?

Any platform integrates through the same two pieces — an issuer/verifier config
and a claims-mapping adapter. Use the raw [token spec](../reference/token.md)
directly (the proxy needs no SDK), or model a new adapter on the closest one
above. The [conformance kit](../integrating/sdk.md#conformance-kit) verifies that
your adapter emits a valid token.
