# Deployment patterns

Warden runs as a stateless process on the MCP path. There are two topologies.

## Sidecar proxy (preferred)

One Warden per agent runtime/session, on the MCP stdio (or loopback HTTP) path.

```text
┌ agent pod / session ─────────────────────────┐
│  agent  --(MCP stdio)-->  warden  --> tools   │
└───────────────────────────────────────────────┘
```

- **Surgical revocation** — pausing/reloading one process affects one agent.
- **Strong isolation** — each agent's trust boundary is its own.
- **Simple identity** — a single session principal (`--token`) per sidecar.

This matches the MVP and most single-tenant deployments. It's the default in the
[provider guides](../providers/index.md).

## Shared gateway

One Warden (HTTP) fronting many agents.

```text
agent A ─┐
agent B ─┼──(MCP HTTP)──> warden gateway ──> tools
agent C ─┘
```

- **Simpler to operate** — one process to run and scale horizontally.
- **Per-request identity** — each `tools/call` carries its *own* bearer
  delegation token (`--request-identity`), so every call is attributed to its
  accountable human even though one gateway serves many users. Combine with
  `require_identity` so a call without a valid token fails closed.
- **Trade-off** — it concentrates the trust boundary and forfeits surgical
  revocation (use the signed revocation feed for fine-grained revoke).

> `--token` (one session principal) and `--request-identity` (per-call bearer)
> are **mutually exclusive** — pick one per process.

## Scaling & resilience

- **Concurrency** — thread-per-request; a held approval blocks only its worker.
- **Disposability** — fast start; `SIGTERM`/`SIGINT` drain in-flight calls
  (`--drain-timeout`) then sign a final audit checkpoint; `SIGHUP` hot-reloads
  policy.
- **Upstream resilience** — per-call timeouts and auto-restart of a crashed/hung
  tool server, with clean errors to the agent.
- **Durable state** — audit log, approval queue, and durable budget are attached
  backing services; put them on a durable volume or ship to WORM/SIEM.

## TLS & the network edge

Warden's HTTP transport speaks plain MCP Streamable-HTTP; terminate **TLS/mTLS at
the edge** (a front proxy / service mesh) and bind Warden to loopback in sidecar
mode. Put a bearer on the surface with `--http-auth-token`.

See [Operating in production](./production.md) for the full hardening checklist.
