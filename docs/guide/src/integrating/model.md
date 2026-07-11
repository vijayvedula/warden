# The integration model

Warden integrates with any agentic platform through **one interface: a signed
token**. That is deliberately the *only* coupling point. Consequently, adopting
Warden on a new platform requires exactly two things:

1. **An issuer/verifier config** — trust the platform's token issuer (its JWKS
   endpoint or public key, and the expected `aud`).
2. **A claims-mapping adapter** — translate the platform's native identity into
   Warden's canonical claims (`sub`, `act`, `roles`, `attrs`, `rel`, `scope`).

Everything expensive — relationship resolution, role expansion, on-behalf-of
exchange — stays on the platform side, where it already lives. Warden verifies
and evaluates. This is what keeps a single Warden build portable across clouds.

## The token is the interface

Every provider has (a) a token/credential issuer, (b) an on-behalf-of/delegation
mechanism, (c) an attribute facility, and increasingly (d) MCP as the tool
transport. Warden consumes all four through the one token, and sits as the MCP
proxy between the platform's agent runtime and its tool servers.

| Warden claim | Databricks | AWS | Google | Azure |
|---|---|---|---|---|
| `sub` (accountable human) | OBO user | human behind the role chain | OIDC `sub` / DWD subject | Entra `oid`/`upn` |
| `act` (delegation) | service principal | STS session | service account | managed identity (OBO) |
| `roles` (RBAC) | UC groups | IAM roles | IAM roles | Entra app roles |
| `attrs` (ABAC) | workspace/catalog | STS session tags | IAM conditions | directory attrs |
| `rel` (ReBAC) | UC grants on securables | resource tags | resource-level IAM | Azure RBAC assignments |
| `scope` (agent grant) | registered UC functions | session policy | agent-card capabilities | delegated scopes |

## Two kinds of adapter (composed, not four interchangeable ones)

| Kind | Examples | Job |
|------|----------|-----|
| **Identity adapter** | Databricks, AWS, Google, Azure | Shape the Warden token from the platform's native credential |
| **Orchestration shim** | LangGraph, Google ADK | Route the framework's tool calls through the Warden proxy and attach the token |

A framework like LangGraph has no `sub` to anchor to — it runs *on top of* a
cloud, so its orchestration shim **composes with** an identity adapter. The SDK
is therefore *(orchestration shim per framework) × (identity adapter per
platform)*, composed.

## The no-forged-authority rule

From Warden's perspective an adapter is **untrusted client code** — it runs on
the side Warden exists to police. Therefore:

> An adapter **orchestrates the platform's native token exchange; it never signs
> authority itself.** The trusted signer stays the platform issuer
> (Databricks / IAM / STS / AgentCore Identity / Entra); the adapter only shapes
> claims and asks the issuer to sign. Warden verifies against the issuer's JWKS.

Done correctly, the SDK is pure convenience with **no new trust surface**. And
because the token spec is the real contract, the proxy **always** accepts a raw
conforming token with no SDK at all.

## Next

- [Deployment patterns](./deployment.md) — sidecar vs shared gateway.
- [The Python SDK](./sdk.md) — the adapters and shims in code.
- Your [provider guide](../providers/index.md) — the end-to-end walkthrough.
