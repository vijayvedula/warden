# Security Policy

Warden is an action control plane -- a security product. We take vulnerabilities
seriously and welcome coordinated disclosure.

## Reporting a vulnerability

**Please do not open public issues for security vulnerabilities.**

- Use **GitHub Private Vulnerability Reporting** — the "Report a vulnerability"
  button on the repository's **Security** tab (preferred).

Include: affected version/commit, a description, reproduction steps or PoC,
impact, and any suggested remediation.

### Our commitment
- **Acknowledge** within **3 business days**.
- **Triage + severity** (CVSS) within **7 business days**.
- **Fix timeline** shared after triage; Critical/High prioritized.
- **Credit** in the advisory and a `SECURITY-HALL-OF-FAME.md` (unless you prefer
  to remain anonymous).
- A **CVE** is requested for confirmed vulnerabilities.

### Safe harbor
Good-faith research under this policy is authorized: we will not pursue legal
action for testing that respects the scope below, avoids privacy violations and
service degradation, and gives us reasonable time to remediate before public
disclosure (default coordinated-disclosure window: **90 days**).

## In scope

The highest-value targets (see [docs/threat-model.md](docs/threat-model.md)):

- **Bypass of the decision pipeline** -- reaching a tool without passing policy.
- **Audit forgeability** -- rewriting/rolling-back the hash chain or defeating the
  signed anchor.
- **Identity/accountability bypass** -- token verification, alg confusion, JWKS
  spoofing, DPoP replay or key-binding, issuer/aud confusion.
- **Authorization bypass** -- RBAC/ABAC/ReBAC or scope escape; the AuthZEN PDP.
- **Revocation bypass** -- acting after a revocation/expiry.
- **Crypto flaws** -- JOSE usage, hash-chain construction, JWK thumbprint, SET
  signing.
- **Fail-open conditions** -- any dependency failure that yields "allow."
- **HTTP surface** -- authN, DPoP enforcement, the PDP/metrics endpoints.

## Out of scope

- Findings requiring a full host/root compromise that already holds the signing
  keys (a documented non-goal until KMS/HSM integration).
- Prompt injection *inside* the agent's reasoning (Warden bounds *actions*, not
  the model -- by design).
- The `--token-key` dev-envelope path (development only; not a production
  verification mode).
- Issues in third-party MCP servers / tools / identity providers themselves.
- Self-inflicted misconfiguration (e.g., `default = "allow"` with no rules, or
  running enforcement without an audit you're comfortable with -- see below).

## Supported versions

Pre-1.0 (beta): the latest `main` and the most recent tagged release receive
security fixes. Pin a release for production.

## Beta / production-use notice

Warden is in **beta** and has **not yet undergone an independent security
audit** (planned -- see [docs/production-readiness.md](docs/production-readiness.md)).
Recommended adoption:

1. **Observe mode first** -- run audit-only (record, don't block). Full value
   (visibility, tamper-evident trail) at near-zero risk; the enforcement path is
   not load-bearing.
2. **Enforce** high-risk tools after you've validated policy in your environment.
3. For **regulated / high-stakes enforcement**, conduct your own review until the
   public audit lands.

## Hardening checklist (operators)

- Verify tokens with a real JWKS/issuer (not the dev envelope); enable
  `--require-at-jwt`.
- Sender-constrain tokens with **DPoP** on the HTTP transport.
- Put an authN token on the HTTP surface (`--http-auth-token`); terminate
  TLS/mTLS at the edge; bind to loopback in sidecar mode.
- Keep signing keys in KMS/secrets, never beside the audit file.
- Ship audit to **WORM/SIEM**; schedule `warden audit verify` (+ anchor verify).
- Run `cargo audit` / `cargo deny` in your build; pin a release.
