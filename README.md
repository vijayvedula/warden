# Warden

**An action control plane for AI agents.** Warden sits as an **MCP proxy**
between an agent and its tool servers. Every `tools/call` is checked against
policy -- **allow / deny / require-approval** -- held for a human when required,
and recorded in a **tamper-evident audit chain**.

<p align="center">
  <a href="https://vijayvedula.github.io/warden/explainers/warden-overview.html">
    <img src="docs/media/warden-overview.gif" alt="Warden in 15 seconds: a proxy on the action boundary that verifies identity, applies policy, and records every call" width="820">
  </a>
</p>
<p align="center">
  <em>▶ <a href="https://vijayvedula.github.io/warden/explainers/warden-overview.html">Watch the full interactive explainer</a> &middot; <a href="https://vijayvedula.github.io/warden/explainers/">all explainers</a></em>
</p>

The thesis: in the agentic era the binding constraint is *trust, not capability*.
Capability is the labs' game; the open problem is letting autonomous agents
**act** with bounded authority, verifiable behaviour, and accountability. Warden
is the *brake* and the *black-box recorder* for agent actions.

> Beta: single-node, file-backed; MCP over stdio or HTTP. Core paths have been
> through an adversarial security review (see [SECURITY.md](SECURITY.md) and
> [docs/production-readiness.md](docs/production-readiness.md)) but not yet an
> independent audit — run observe-only first, pin a release for enforcement.

## Quickstart

```sh
cargo build

# 1. Self-contained walkthrough -- no API key, no external server.
./target/debug/warden demo

# 2. Verify the tamper-evident audit chain (then edit a line and re-run to see it caught).
./target/debug/warden audit verify --audit .warden-demo/audit.jsonl
```

The demo drives a simulated agent through allow / budget / deny / hold-for-approval
(approved *and* denied), then prints the audit trail and verifies the hash chain.

## Use it as a real MCP proxy

Point your MCP client at Warden instead of the tool server; Warden launches the
real server as its upstream:

```sh
./target/debug/warden proxy \
  --upstream "python3 examples/echo_mcp_server.py" \
  --agent prod-agent \
  --policy warden.policy.toml
```

Allowed calls forward to the upstream; denied calls are blocked before they ever
reach it; held calls wait for `warden approve`/`warden deny`. Everything is
appended to `.warden/audit.jsonl`.

```sh
warden approvals list                 # pending held actions
warden approve <id> --by alice        # release one
warden deny <id> --by security
warden audit tail                     # what agents did
warden audit verify                   # prove the record wasn't altered
```

## Policy

First matching rule wins; otherwise `default` applies. See
[`warden.policy.toml`](warden.policy.toml).

```toml
default = "allow"

[[rules]]
tool = "delete_database"
decision = "deny"

[[rules]]
tool = "wire_funds"
when = { arg = "amount", op = "gt", value = 1000 }   # condition on a tool arg
decision = "require_approval"

[[rules]]
tool = "write_file"
decision = "allow"
max_per_run = 20                                      # per-run budget

[[rules]]
tool = "admin_*"                                      # wildcard match
decision = "require_approval"
```

## How it works

```
agent -- tools/call --> Warden --+- policy: allow -----> upstream MCP server -> result
                                 |- policy: deny ------> blocked (tool error)
                                 \- require_approval --> held -> human -> allow/deny
                                          |
                                          \- every decision > tamper-evident audit chain
```

- **Policy engine** (`policy.rs`) -- allow/deny/require-approval by tool, arg
  condition, and per-run budget.
- **Approval queue** (`approvals.rs`) -- file-backed so a separate reviewer
  process can resolve a held action.
- **Audit chain** (`audit.rs`) -- each entry's hash covers its content plus the
  previous hash; altering any past entry breaks the chain (try it).
- **Gateway** (`gateway.rs`) -- the intercept/decide/forward/record loop.
- **Upstream** (`upstream.rs`) -- real MCP server over stdio, or the in-process
  demo server.

## Adopt it on your platform

Warden's only coupling point is a single signed token (RFC 8693 delegation:
`sub` = accountable human, `act` = the acting chain, plus RBAC/ABAC/ReBAC/scope).
Any platform integrates by mapping its native identity to that token -- pure data
mapping, no policy logic. The [**warden-sdk**](sdk/python/) ships that glue:

- **Identity adapters** -- Databricks (OBO + Unity Catalog), AWS Bedrock
  (STS AssumeRole + session tags), Google ADK / Vertex (workload identity),
  Azure AI Foundry (Entra ID + OBO).
- **Orchestration shims** -- LangGraph, Google ADK: point the agent's MCP client
  at `warden proxy` with one line.
- **Conformance kit** -- a token is valid iff it passes `warden token verify`;
  the kit checks first-party *and* community adapters against that ground truth.

Runnable adoption examples per platform live in [`examples/`](examples/). See
[docs/platform-integration.md](docs/platform-integration.md) for the full mapping
and [docs/twelve-factor.md](docs/twelve-factor.md) for cloud-native operation
(all config via `WARDEN_*` env; see [`.env.example`](.env.example)).

## User guide

The **[Warden User Guide](https://vijayvedula.github.io/warden/)** is the full,
navigable handbook — concepts, getting started, the integration model, and a
**separate end-to-end guide for each provider**:

- [LangGraph](https://vijayvedula.github.io/warden/providers/langgraph.html) ·
  [AWS Bedrock](https://vijayvedula.github.io/warden/providers/aws-bedrock.html) ·
  [Databricks](https://vijayvedula.github.io/warden/providers/databricks.html) ·
  [Google ADK](https://vijayvedula.github.io/warden/providers/google-adk.html) ·
  [Azure AI Foundry](https://vijayvedula.github.io/warden/providers/azure-ai.html)

The guide is an [mdBook](https://rust-lang.github.io/mdBook/) built from
[`docs/guide/`](docs/guide/) and published to GitHub Pages alongside the
explainers.

## Roadmap (the trust-layer wedge)

- **Recovery / undo** -- compensating actions for reversible tool calls.
- **Richer policy** -- rate windows, spend budgets, data-class conditions, OPA/Rego.
- **Multi-tenant control surface** + a hosted approval UI.
- **More adapters** -- OpenAI Agents SDK, CrewAI, AutoGen; TS/JS token builder.
- **Externally-anchored audit** -- a public transparency log for the signed anchor.

## Explainers

Short **animated explainers** (self-contained HTML decks). Browse them all at the
**[explainers index](https://vijayvedula.github.io/warden/explainers/)**, or jump straight in:

**Core**
- [The Platform](https://vijayvedula.github.io/warden/explainers/warden-overview.html) — what Warden is and the problem it solves
- [Accountable Authorization](https://vijayvedula.github.io/warden/explainers/accountable-authorization.html) — the token-as-interface trust model
- [Reference Architecture](https://vijayvedula.github.io/warden/explainers/reference-architecture.html) — how the pieces fit together
- [Threat Model](https://vijayvedula.github.io/warden/explainers/threat-model.html) — what Warden defends, and what it doesn't

**Integrations** (pair with the runnable [`examples/`](examples/))
- [Platform Integration](https://vijayvedula.github.io/warden/explainers/platform-integration.html) — the one coupling point, mapped to any platform
- [Warden × Databricks](https://vijayvedula.github.io/warden/explainers/integration-databricks.html) · [× AWS](https://vijayvedula.github.io/warden/explainers/integration-aws.html) · [× Google](https://vijayvedula.github.io/warden/explainers/integration-google.html) · [× LangGraph](https://vijayvedula.github.io/warden/explainers/integration-langgraph.html)

> The decks are published from [`docs/explainers/`](docs/explainers/) via GitHub
> Pages. Enable it once the repo is public: **Settings → Pages → Source: GitHub
> Actions**. Until then the source HTML renders locally in any browser.

## License

Dual-licensed under either of **[MIT](LICENSE-MIT)** or
**[Apache-2.0](LICENSE-APACHE)** at your option. Contributions are accepted under
the same terms; see [CONTRIBUTING.md](CONTRIBUTING.md).
