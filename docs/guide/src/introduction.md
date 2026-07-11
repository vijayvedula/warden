# Warden User Guide

**Warden is an action control plane for AI agents.** It sits as an **MCP proxy**
between an agent and its tool servers. Every `tools/call` is checked against
policy — <code class="allow">allow</code> / <code class="deny">deny</code> /
<code class="hold">require-approval</code> — held for a human when required, and
recorded in a **tamper-evident audit chain**.

The thesis: in the agentic era the binding constraint is *trust, not capability*.
Capability is the labs' game; the open problem is letting autonomous agents
**act** with bounded authority, verifiable behaviour, and accountability. Warden
is the *brake* and the *black-box recorder* for agent actions.

```text
agent -- tools/call --> Warden --+- policy: allow -----> upstream MCP server -> result
                                 |- policy: deny ------> blocked (tool error)
                                 \- require_approval --> held -> human -> allow/deny
                                          |
                                          \- every decision -> tamper-evident audit chain
```

## Who this guide is for

Engineers deploying or integrating AI agents that **take actions** — call tools,
query data, move money, file tickets — and who need those actions to be
governed, attributable, and auditable. You should be comfortable with the
command line and your agent framework of choice.

## How to read it

- **[Concepts](./concepts/what-is-warden.md)** — the model: the proxy, the
  identity token, policy, and the audit chain. Read this first.
- **[Getting started](./getting-started/install.md)** — build Warden, run the
  self-contained demo, then govern your first real agent.
- **[Integrating Warden](./integrating/model.md)** — the token-as-interface
  integration model, deployment patterns, the Python SDK, configuration, and
  production operations.
- **[Provider guides](./providers/index.md)** — a **separate, end-to-end guide**
  for each Agentic AI provider: **LangGraph**, **AWS Bedrock (AgentCore)**,
  **Databricks (Mosaic AI)**, **Google ADK / Vertex AI**, and **Azure AI
  Foundry**. Jump straight to yours.
- **[Reference](./reference/cli.md)** — CLI, policy, token spec, and security.

## The 30-second version

1. Point your agent's MCP client at `warden proxy` instead of the tool server.
2. Give Warden a signed token that says *who the agent acts for* (or run
   audit-only to start).
3. Write a policy: which tools are allowed, denied, or need a human.
4. Every call is now gated and recorded. Prove it with `warden audit verify`.

> **New to Warden?** Watch the [animated overview](https://vijayvedula.github.io/warden/warden-overview.html)
> for a two-minute visual tour, then come back here.
