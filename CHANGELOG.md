# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
Hardening pass from an adversarial review of the security-critical paths.
- **Decision pipeline fail-closed:** a `tools/call` with a missing/non-string
  `name` is now denied and audited, not forwarded to the upstream ungated.
- **Audit hash integrity:** the tamper-evident row hash is computed over a
  canonical JSON encoding instead of a `|`-delimited join, closing a
  field-boundary collision that could rewrite a record without breaking the
  chain. (Chains written by earlier builds will not re-verify — regenerate.)
- **Token audience/issuer binding:** JWT verification now *requires* `aud`/`iss`
  when `--aud`/`--iss` are configured (previously an absent claim passed).
- **HTTP DoS:** an oversized/unparseable `Content-Length` is rejected (413/400)
  before allocation, fixing a one-request process abort; accepted sockets get
  read/write timeouts (slowloris) and no longer drop fragmented requests.
- **Post-approval re-validation:** revocation and token freshness are re-checked
  after an approval wait, so authority withdrawn during the wait is honored.
- **Atomic budgets:** `max_per_run` is reserved atomically at forward time,
  removing a check-then-increment race that let concurrent calls overshoot.
- **Policy numeric coercion:** numeric `gt`/`lt`/`eq` conditions accept a
  number sent as a string, closing a threshold-gate bypass.
- **Redaction of numeric leaves:** PII/PANs sent as JSON numbers are now scanned
  and redacted (previously only strings were).
- **DPoP:** `iat` is now required (RFC 9449); proofs without it are rejected.
- **Per-request identity:** a missing/invalid bearer in per-request mode yields
  an unauthenticated principal (never the session principal); `--token` and
  `--request-identity` are mutually exclusive.
- **Outbound JWKS/OIDC fetch:** requires `https`, with connect/read timeouts, a
  capped redirect chain, and a body-size limit (SSRF/DoS hardening).
- Smaller: OCSF success-status precedence fix, escaped `decision` in JSON logs,
  bounded upstream response read, and a `verify` note that rollback is only
  detectable with a signed anchor.

### Added
- Public open-source release.
- Source-available licensing under the **Functional Source License 1.1
  (FSL-1.1-ALv2)**: free for any use except a Competing Use, with each version
  converting to Apache-2.0 two years after its release.
- `warden-sdk` (Python): token builder, conformance kit, identity adapters
  (Databricks, AWS Bedrock/STS, Google ADK, Azure Entra ID) and orchestration
  shims (LangGraph, Google ADK).
- Adoption examples for each supported platform under `examples/`.
- 12-factor configuration: every option is settable via `WARDEN_*` environment
  variables (flag › env › config file › default). See `docs/twelve-factor.md`.
- Continuous delivery: tagged releases publish cross-platform binaries, the
  Python SDK, and a container image.

## [0.1.0] — MVP

### Added
- MCP proxy that gates every `tools/call`: allow / deny / require-approval.
- Tamper-evident, hash-chained audit log with signed checkpoint anchoring.
- File-backed approval queue with optional signed approver assertions.
- RFC 8693 delegation identity (`sub`/`act`), JWT + JWKS verification, DPoP
  sender-constraint, RFC 9068 `at+jwt` enforcement.
- Policy engine: RBAC / ABAC / ReBAC, per-run budgets, arg/subject/resource
  conditions, wildcard tool matching.
- HTTP (MCP Streamable-HTTP) and stdio transports.
- Pause/resume control plane and signed revocation feed.
- OCSF event sink and PII/secret redaction profiles.

[Unreleased]: https://github.com/vijayvedula/warden/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/vijayvedula/warden/releases/tag/v0.1.0
