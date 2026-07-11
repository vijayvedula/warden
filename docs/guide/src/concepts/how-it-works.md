# How it works

Warden launches your real MCP tool server as its **upstream** and speaks MCP to
the agent on the front. The agent thinks it is talking to the tool server; every
`tools/call` actually passes through Warden's decision pipeline first.

```text
agent --(MCP, stdio/HTTP)--> Warden --(MCP, spawns upstream)--> tool server
                              |
                              | 1. verify identity     (who acts?)
                              | 2. check revocation    (still authorized?)
                              | 3. evaluate policy     (allowed? held? denied?)
                              | 4. reserve budget      (within the cap?)
                              | 5. forward / hold / block
                              | 6. record to the audit chain
```

## The decision pipeline (in order)

Every `tools/call` runs the same gauntlet. **Any failure denies** — Warden fails
closed.

1. **Handshake** — optionally require the MCP `initialize` before any call.
2. **Pause** — an admin `warden pause` stops forwarding, at Warden, not by
   trusting the agent.
3. **Revocation** — a signed, append-only revocation feed can deny by token
   `jti`, agent, or human (negative authority), checked live.
4. **Identity** — the delegation token is verified (signature, `aud`/`iss`,
   `exp`/`nbf`, and that the token's leaf actor matches this agent). Expired
   session tokens are refreshed-or-denied per call.
5. **Policy** — the first matching rule decides: scope narrowing, RBAC/ABAC/ReBAC
   gates, `when` conditions, and per-run budgets. Otherwise the `default`
   applies.
6. **Approval** — a `require_approval` decision *holds* the call until a human
   releases it (optionally with a signed approver assertion), or it times out.
7. **Forward** — an allowed (or approved) call reserves its budget atomically,
   durably records the authorization, mints a call-context token for the next
   hop, and forwards to the upstream.
8. **Record** — the decision and outcome are appended to the tamper-evident
   audit chain (and any OCSF/SIEM sinks).

A **denied** call never reaches the upstream — the agent receives a clean MCP
tool error (`isError: true`) explaining the block, and the decision is recorded.

## Concurrency

Warden is shared across worker threads (one per in-flight request). A call held
for approval blocks only *its own* worker — the upstream lock is released during
the wait — so other calls keep flowing. Responses correlate by JSON-RPC id, so
out-of-order replies are fine.

## Transports

- **stdio** — the sidecar-per-agent pattern; the agent's MCP client launches
  `warden proxy ...` as a subprocess.
- **HTTP** — MCP Streamable-HTTP (`--http ADDR`), with `GET /healthz` and
  `GET /metrics`, an optional bearer on the surface, and per-request identity for
  a shared gateway.

See the [CLI reference](../reference/cli.md) for every flag.
