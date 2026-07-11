# Operating in production

Warden is **beta**: single-node, file-backed, and it has been through an
adversarial security review but **not yet an independent audit**. Adopt it in
stages.

## Recommended rollout

1. **Observe mode first.** Run audit-only (record, don't block). You get full
   visibility and a tamper-evident trail at near-zero risk — the enforcement path
   isn't load-bearing yet.
2. **Enforce high-risk tools** once you've validated policy in your environment
   (deny the destructive ones, `require_approval` the outbound ones).
3. **For regulated / high-stakes enforcement**, conduct your own review until the
   public audit lands.

## Hardening checklist

- **Identity** — verify tokens against a real JWKS/issuer (`--jwks-url`/`--aud`),
  not the dev envelope; enable `--require-at-jwt` (RFC 9068).
- **Sender-constrain** tokens with **DPoP** on the HTTP transport.
- **Network** — put a bearer on the HTTP surface (`--http-auth-token`), terminate
  TLS/mTLS at the edge, bind to loopback in sidecar mode.
- **Keys** — keep signing keys in KMS/secrets, never beside the audit file.
- **Evidence** — enable the signed `--anchor`; ship the audit + anchor to
  **WORM/SIEM** (`--ocsf`, sinks); schedule `warden audit verify` (+ anchor
  verify) in monitoring.
- **Fail-closed evidence gate** — use a **blocking** sink where "no action
  without a durable record" is required (a failed audit *write* alone is
  non-blocking by default — an availability choice).
- **Supply chain** — run `cargo audit` / `cargo deny` in your build; pin a
  release.
- **Policy** — run `warden policy lint` in CI; start restrictive; iterate with
  `warden policy test` and hot-reload (`SIGHUP`).

## Observability

- `--log-format json` — one structured decision line per call (tool, decision,
  outcome, latency, accountable, `jti`) with OpenTelemetry fields.
- `GET /healthz`, `GET /metrics` on the HTTP transport; `--metrics FILE` and a
  drain summary for stdio.
- `--ocsf FILE` — OCSF events for your SIEM.

## Revocation & incident response

- **Pause** everything at Warden: `warden pause` / `warden resume` (a running
  proxy reloads policy on resume).
- **Revoke** live, without a restart, via the signed feed:
  `warden revoke --jti … | --agent … | --human … --revoke-key admin.pem`. The
  proxy tails it and denies matching calls immediately.

## Known residuals

These are tracked and documented in
[docs/production-readiness.md](https://github.com/vijayvedula/warden/blob/main/docs/production-readiness.md):
plain `verify` needs the anchor to detect tail rollback; approval assertions can
replay against a byte-identical action (a per-request nonce is the fix); tool
matching is case-exact; host/root compromise holding the signing keys is out of
scope until KMS/HSM integration.

See the [security reference](../reference/security.md) and
[SECURITY.md](https://github.com/vijayvedula/warden/blob/main/SECURITY.md).
