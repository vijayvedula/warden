# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Public open-source release.
- Dual licensing under **MIT OR Apache-2.0**.
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
