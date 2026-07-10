# Warden -- Threat Model

> STRIDE threat model over Warden's trust boundaries. Doubles as the review
> package for an external/OSTIF audit. Companion to
> [accountable-authorization.md](accountable-authorization.md) and the
> architecture diagrams ([logical](warden-logical-architecture.svg),
> [DFD](warden-dfd.svg), [network](warden-network-architecture.svg),
> [resilience](warden-resilience.svg)).

## 1. System in one paragraph

Warden is an MCP proxy that sits between an AI agent and its tool servers. Every
`tools/call` is verified against a signed identity token and a policy, then
allowed / blocked / held-for-human, and recorded in a tamper-evident,
hash-chained, externally-anchored audit log. It speaks standards on the way in
(OIDC/JWT, DPoP, RFC 8693) and out (OCSF, CAEP, OpenTelemetry, AuthZEN,
Transaction-Tokens). Single Rust binary; stdio or HTTP transport; sidecar or
gateway deployment.

## 2. Assets / crown jewels (what an attacker wants)

| # | Asset | Why it matters |
|---|-------|----------------|
| A1 | **The enforcement decision** | If the brake can be bypassed, the entire product is void. |
| A2 | **The audit chain** | The accountability record; must be unforgeable and non-repudiable. |
| A3 | **Identity / accountability binding** | "Which human is answerable" must be sound and unspoofable. |
| A4 | **Signing keys** (anchor, approval, txn, sink, revoke) | Compromise forges evidence, approvals, or revocations. |
| A5 | **Tool/data access** | The thing agents act on (DB, DevOps, money movement). |
| A6 | **Policy** | Defines what's permitted; tampering weakens the brake. |

## 3. Threat actors

- **TA1 -- Compromised / misbehaving agent** (the *primary* adversary; untrusted by design): prompt-injected or buggy, tries to exceed its authority, replay credentials, or reach tools it shouldn't.
- **TA2 -- Network attacker** on the agent↔Warden↔tools / IdP paths.
- **TA3 -- Malicious insider / local attacker** with host or file access (audit log, config, keys).
- **TA4 -- Compromised upstream tool / MCP server.**
- **TA5 -- Compromised peer agent (A2A)** presenting a forged Transaction-Token.
- **TA6 -- Compromised downstream sink/endpoint** (SIEM/SSF webhook).

## 4. Trust boundaries

1. **Agent -> Warden** (TA1): the agent is *untrusted*; Warden is the enforcement point. Stdio (in-process) or HTTP (loopback / edge-terminated).
2. **Warden -> IdP/JWKS** (TA2): read-only fetch of public keys over TLS.
3. **Warden -> upstream tools** (TA4): only allowed calls forwarded.
4. **Warden ↔ admin/control plane** (TA3): signed revocation feed, control file, signing keys (KMS).
5. **Warden -> sinks** (TA6): outbound evidence/signals.
6. **Warden ↔ peer Warden (A2A)** (TA5): Transaction-Token propagation.
7. **Process boundary / host** (TA3): the audit log, config, and key material at rest.

## 5. STRIDE analysis

Legend for status: [x] mitigated / [~] partial / residual / [ ] open (tracked).

### Spoofing (identity)
| Threat | Mitigation | Status |
|---|---|---|
| Agent forges a token / signs with public key (alg confusion) | Asymmetric-only JWT verification; HMAC excluded; `kid`/JWKS or PEM ([identity.rs](../src/identity.rs)) | [x] |
| Agent presents someone else's bearer token | **DPoP** sender-constraint: token `cnf.jkt` bound to a holder key; per-request proof ([dpop.rs](../src/dpop.rs)) | [x] |
| Replay of a captured DPoP proof | Per-`jti` replay cache within the freshness window | [x] |
| Wire identity != token actor | Leaf `act` must equal the connecting agent | [x] |
| Spoofed issuer | Issuer allowlist (`--iss`), `aud` check, RFC 9068 `typ` | [x] |
| Forged approval ("approved by alice") | Signed per-action assertion bound to action id; approver allowlist (JWKS) ([approval_sig.rs](../src/approval_sig.rs)) | [x] |
| Forged inbound A2A Txn-Token | ES256 verify against `--txn-verify-key`; invalid => fail closed ([txntoken.rs](../src/txntoken.rs)) | [x] |
| Unauthenticated caller on the HTTP surface | Bearer authN (constant-time), `/healthz` excepted ([http.rs](../src/http.rs)) | [x] |
| Stolen long-lived key | Keys -> KMS/HSM; rotation | [ ] (go-live) |

### Tampering
| Threat | Mitigation | Status |
|---|---|---|
| Rewrite an audit row | SHA-256 hash chain; accountability folded into the hash ([audit.rs](../src/audit.rs)) | [x] |
| Roll back / truncate the audit log | ES256 signed anchor checkpoints; rollback detected on verify ([anchor.rs](../src/anchor.rs)) | [x] |
| Local attacker recomputes the whole chain | Anchor is signed by a key the proxy doesn't need to hold to *verify*; ship to WORM / transparency log | [~] (anchor done; live WORM/Rekor sink = go-live) |
| Tamper with policy on disk | Policy-as-code in Git/CI; reload is explicit (SIGHUP/resume); bad policy => keep last-good | [~] (integrity = signed policy: open) |
| Tamper with the in-flight request | stdio in-process; HTTP via TLS at edge | [~] (mTLS = deployment) |
| Concurrent writers corrupt the chain | Exclusive advisory file lock; single-writer; O(1) head cache | [x] |

### Repudiation
| Threat | Mitigation | Status |
|---|---|---|
| "It wasn't my agent" | Every action carries the accountable human + `act` chain + token `jti`, hash-chained | [x] |
| Drop evidence silently | Append-only chain + `audit verify`; **blocking sinks** = no action without acked evidence; dropped fail-safe events are logged | [x] |
| Multi-hop blame-shifting (A2A) | Txn-Token chain extension records every hop | [x] |

### Information disclosure
| Threat | Mitigation | Status |
|---|---|---|
| Secrets/PII in audit & sink events | Redaction at the OCSF/CAEP projection | [ ] (go-live) |
| Read `/metrics`, PDP, audit over HTTP | Bearer authN on HTTP surface | [x] |
| Token/claims leak over the wire | TLS (edge); tokens are bearer-min + DPoP-bound | [~] |
| Key material on disk | KMS/HSM; never co-located with audit | [ ] (go-live) |
| Env attributes spoofed to widen access | Unsigned/local inputs may only *narrow*, never grant (policy invariant) | [x] |

### Denial of service / availability
| Threat | Mitigation | Status |
|---|---|---|
| Hung / crashed upstream blocks everything | Per-call timeout + auto-restart; worker-per-request ([upstream.rs](../src/upstream.rs)) | [x] |
| A held approval blocks all traffic | Holds block only their own worker | [x] |
| Slow/down sink stalls the action path | Fail-safe sinks tail the WAL off the hot path (incremental, retry) | [x] |
| Down IdP / revocation feed / control plane | Degrade-safe: existing tokens to exp, set only denies, short-TTL + holds | [x] |
| Unbounded inputs / parser crash | Fuzzing of JSON-RPC/JWT/policy parsers; fail-closed on parse error | [~] (fuzzing in CI; soak = go-live) |
| Resource exhaustion (thread-per-request) | Bounded worker pool; rate limits | [ ] (go-live) |
| No graceful drain on shutdown | SIGTERM + bounded drain | [ ] (go-live) |

### Elevation of privilege (the core)
| Threat | Mitigation | Status |
|---|---|---|
| **Reach a tool without passing the decision pipeline** | All `tools/call` route through `dispatch`; non-tool methods pass through but can't *act*; deny-overrides | [x] |
| Exceed delegated authority | `effective = scope & role & rel & attrs`; scope narrowing; RBAC/ABAC/ReBAC ([policy.rs](../src/policy.rs)) | [x] |
| Act on a resource with no relationship | ReBAC `require_relation` set-membership on carried tuples | [x] |
| Keep acting after revocation | Event-driven revocation checked inline (step 0b); fail closed | [x] |
| Keep acting after token expiry | Per-action freshness: refresh-or-deny | [x] |
| Bypass budget by restarting | Durable budget file | [x] |
| TOCTOU / concurrency race opens a gap | Interior-mutability with per-resource locks; (residual: budget reserve is not cross-process atomic) | [~] |
| Fail-open on any dependency failure | Fail-closed by default everywhere (see Sec 6) | [x] |

## 6. The fail-closed argument (the central claim)

**No single dependency outage can produce an over-permissive decision.** For
each dependency, failure => deny, never silent allow:

- No accountable identity / unverifiable token => **deny**.
- Expired token, unrefreshable => **deny**.
- Bad/forged signature (token, approval, feed, Txn-Token) => **reject**.
- IdP/JWKS unreachable => new sessions **deny**; verified ones run to `exp`.
- Revocation feed stale/unreachable => set only adds denies; Layer-3 holds remain.
- Control/admin plane down => short TTL + holds; pause is local.
- Bad policy reload => keep last-good; no outage.
- High-assurance sink unavailable => action **held/denied** (no action without evidence).
- Upstream crash/hang => clean error + restart, never a bypass.

Worst case is always **"deny and record,"** never "allow silently."

## 7. Assumptions

- The host running Warden, and Warden's own binary, are trusted (a host
  compromise that holds the signing keys is out of scope -- mitigated by KMS).
- The identity issuer correctly mints tokens (the carried claims are trusted
  after signature verification -- Warden offloads relationship/role resolution).
- TLS is terminated correctly at the edge for the HTTP transport.
- Clocks are loosely synchronized (leeway configurable).
- For single-node deployments, one Warden owns its audit/budget/approval files.

## 8. Security non-goals (explicitly out of scope, v1)

- Defending against a full host/root compromise that exfiltrates signing keys
  (-> KMS/HSM, attestation).
- Preventing prompt injection *inside* the agent (Warden bounds the agent's
  *actions*, not its reasoning -- that's the design).
- Multi-tenant isolation on a shared gateway beyond process boundaries.
- Confidentiality of tool payloads at the tool (Warden governs the action, not
  the tool's own data handling).

## 9. Residual risks tracked to go-live

KMS for keys / PII/secret redaction in projections / SIGTERM/graceful drain /
bounded worker pool + rate limits / multi-process atomic budget reservation /
signed policy integrity / live WORM/Rekor anchor sink / mTLS / soak/fuzz depth.
See [production-readiness.md](production-readiness.md) and
[standards.md](standards.md).

## 11. Supply-chain advisories (tracked acceptances)

The CI security pipeline (`cargo-audit` + `cargo-deny`) gates the dependency
tree. Accepted advisories are documented here with justification (never silently
ignored):

| Advisory | Crate | Assessment | Status |
|---|---|---|---|
| **RUSTSEC-2023-0071** (Marvin RSA timing sidechannel) | `rsa` (transitive via `jsonwebtoken` rust_crypto) | **Not applicable** -- Warden does RSA signature *verification* only (public-key ops); it holds no RSA private keys, so the private-key timing sidechannel has no surface. | Accepted; remediation tracked -> switch `jsonwebtoken` to the `aws_lc_rs` provider (no `rsa` crate, FIPS-capable). |

## 10. How this maps to an audit

Crown jewels (Sec 2) -> trust boundaries (Sec 4) -> STRIDE (Sec 5) -> the fail-closed proof
(Sec 6). An assessor should focus on **A1 (bypass), A2 (audit forgeability), A3
(identity binding)**, the crypto usage (JOSE/DPoP/SET/hash-chain/thumbprint),
and hunting **any fail-open** path that violates Sec 6.
