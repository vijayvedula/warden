# Security & threat model

Warden is a security product; this page summarises its posture and points at the
authoritative documents. Report vulnerabilities via **GitHub Private
Vulnerability Reporting** — see
[SECURITY.md](https://github.com/vijayvedula/warden/blob/main/SECURITY.md). Do
**not** open public issues for vulnerabilities.

## What Warden defends (highest-value targets)

- **Bypass of the decision pipeline** — reaching a tool without passing policy.
- **Audit forgeability** — rewriting/rolling-back the hash chain or defeating the
  signed anchor.
- **Identity/accountability bypass** — token verification, algorithm confusion,
  JWKS spoofing, DPoP replay/key-binding, issuer/audience confusion.
- **Authorization bypass** — RBAC/ABAC/ReBAC or scope escape.
- **Revocation bypass** — acting after a revocation/expiry.
- **Fail-open conditions** — any dependency failure that yields "allow."

The core invariant is **fail closed**: any ambiguity or dependency failure
results in a deny, never an allow.

## Design guarantees

- **Asymmetric-only JWT** verification; `aud`/`iss` required when configured;
  RFC 9068 `at+jwt` enforcement; DPoP sender-constraint (RFC 9449).
- **Tamper-evident audit** — hash-chained over a canonical, injective encoding of
  every accountability field; signed checkpoints (anchor) detect rollback.
- **Atomic budgets**, **post-approval re-validation** of revocation/freshness,
  and **redaction** of PII/secrets (including numeric leaves) before hashing.

## Out of scope (by design)

- Prompt injection *inside* the agent's reasoning — Warden bounds *actions*, not
  the model.
- Findings requiring a host/root compromise that already holds the signing keys
  (a documented non-goal until KMS/HSM integration).
- The `--token-key` dev-envelope path (development only).
- Issues in third-party MCP servers / tools / identity providers themselves.

## Assurance status

Warden is **beta**. Its security-critical paths went through an **adversarial
security review** (findings fixed with regression tests), but it has **not yet
had an independent third-party audit**. For regulated / high-stakes enforcement,
conduct your own review and run [observe-mode
first](../integrating/production.md).

## Documented residuals

Tracked in
[docs/production-readiness.md](https://github.com/vijayvedula/warden/blob/main/docs/production-readiness.md):
plain `verify` needs the anchor to detect tail rollback; a failed audit *write*
is non-blocking by default (use a blocking sink for strict fail-closed); approval
assertions can replay against a byte-identical action (a per-request nonce is the
fix); tool matching is case-exact.

## Authoritative documents

- [SECURITY.md](https://github.com/vijayvedula/warden/blob/main/SECURITY.md) —
  reporting, scope, safe harbor, hardening checklist.
- [docs/threat-model.md](https://github.com/vijayvedula/warden/blob/main/docs/threat-model.md)
  — the full threat model.
- [docs/production-readiness.md](https://github.com/vijayvedula/warden/blob/main/docs/production-readiness.md)
  — the readiness checklist and residuals.
- The [Threat Model explainer](https://vijayvedula.github.io/warden/threat-model.html).
