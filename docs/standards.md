# Warden -- Standards Support

Warden is **standards-native**: it verifies and emits recognized IETF / OpenID /
OCSF formats rather than bespoke ones, so it drops into existing identity
providers, SIEMs, and policy engines. This maps each standard -> the module that
implements it -> the flag/endpoint that turns it on -> the test that proves it.

Status: [x] implemented / [~] partial (notes) / [ ] roadmap.

## Identity & tokens

| Standard | What Warden does | Module | Flag / endpoint | Test |
|---|---|---|---|---|
| **OAuth 2.0 / OIDC** resource-server | Verify JWT access tokens against issuer keys; OIDC discovery of `jwks_uri` | [identity.rs](../src/identity.rs), [net.rs](../src/net.rs) | `--issuer-url` (discovery), `--iss` (allowlist), `--aud` | `token verify` CLI [x] |
| **JWKS** (live) | Fetch keys over HTTPS, 5-min cache, refetch on key rotation | identity.rs `fetch_jwks` | `--jwks-url URL` (or `--jwks FILE`) | CLI fetch [x] |
| **RFC 8693** Token Exchange (delegation) | `sub` = accountable human, nested `act` = service->agent chain | identity.rs `act_chain` | carried in token | `chain_and_leaf` [x] |
| **RFC 9068** JWT access-token profile | Enforce `typ: at+jwt` | identity.rs | `--require-at-jwt` | `rejects_non_at_jwt_when_required` [x] |
| **JOSE** (JWS/JWA), asymmetric-only | RS/PS/ES/EdDSA; HMAC excluded (blocks RS256->HS256 confusion) | identity.rs `ASYMMETRIC_ALGS` | n/a | `hmac_token_rejected_alg_confusion` [x] |
| **RFC 7800 / RFC 9449 DPoP** sender-constraint | Token `cnf.jkt` bound to a holder key; per-request DPoP proof verified (htm/htu/iat + JWK thumbprint RFC 7638) | [dpop.rs](../src/dpop.rs), [http.rs](../src/http.rs) | (HTTP transport) `DPoP` header | `valid_proof_bound_to_token`, CLI 401 [x] |
| **SPIFFE SVID** (JWT-SVID) | Verified like any OIDC JWT (issuer = SPIRE) | identity.rs | `--jwks-url` / `--iss` | [~] via OIDC path |
| **SD-JWT / VC-DID / mTLS-bound (RFC 8705)** | -- | -- | -- | [ ] roadmap |

## Authorization & policy

| Standard | What Warden does | Module | Flag / endpoint | Test |
|---|---|---|---|---|
| **RBAC / ABAC / ReBAC** | `require_role` / `when` (arg/subject/env/resource, AND/OR/NOT) / `require_relation` | [policy.rs](../src/policy.rs) | `warden.policy.toml` | policy tests [x] |
| **AuthZEN** (OpenID Authorization API) | Expose the engine as a PDP; any PEP can query a decision | [authzen.rs](../src/authzen.rs), http.rs | `POST /access/v1/evaluation` | `authzen_allow_and_deny`, CLI [x] |
| **Cedar / OPA-Rego / OpenFGA** (external PDP/relations) | AuthZEN is the bridge; external engines plug in behind it | authzen.rs | (external) | [~] interface ready |

## Revocation & continuous access

| Standard | What Warden does | Module | Flag | Test |
|---|---|---|---|---|
| **Shared Signals Framework / CAEP** | Tail a signed feed of Security Event Tokens (RFC 8417); map `session-revoked` / `credential-change` / `token-claims-change` -> revoke jti/agent/human | [revocation.rs](../src/revocation.rs) | `--revocations`, `--revocation-pub` | `caep_set_event_applies` [x] |
| Warden-native signed events | `warden revoke --jti/--agent/--human` | revocation.rs | `--revoke-key` | `signed_events_tail_and_apply` [x] |

## Evidence, audit & telemetry

| Standard | What Warden does | Module | Flag | Test |
|---|---|---|---|---|
| **OCSF** (Open Cybersecurity Schema Framework) | Emit each decision as an OCSF "API Activity" (6003) event (SIEM-ready) | [ocsf.rs](../src/ocsf.rs) | `--ocsf FILE` | `ocsf_shape_for_a_denied_action`, CLI [x] |
| **OpenTelemetry** (resource + trace fields) | `service.name` + `trace_id`/`span_id` in JSON decision logs and OCSF metadata | [obs.rs](../src/obs.rs), ocsf.rs | `--log-format json` | obs/ocsf tests [x] |
| **Tamper-evident + transparency** (Merkle / Sigstore-style) | SHA-256 hash chain + ES256 signed anchor checkpoints (rollback/rewrite proof) | [audit.rs](../src/audit.rs), [anchor.rs](../src/anchor.rs) | `--anchor`, `--anchor-key` | anchor rollback test [x] |
| **Sigstore Rekor / RFC 6962 CT log** (external) | Anchor checkpoints can ship to a transparency log | anchor.rs | (external sink) | [~] format ready |

## Multi-hop / A2A

| Standard | What Warden does | Module | Flag | Test |
|---|---|---|---|---|
| **Transaction Tokens** (IETF / WIMSE) | On allow, mint a signed call-context token (`txn`/`sub`/`azd`/`rctx`) and inject into the forwarded request's `_meta`; verify inbound tokens and **extend the act-chain** across hops; forged token fails closed | [txntoken.rs](../src/txntoken.rs), gateway.rs | `--txn-key`, `--txn-verify-key` | `mint_verify_and_extend_chain`, CLI A2A [x] |
| **A2A protocol** transport | Guarded on the same boundary (tokens propagate over MCP `_meta`) | gateway.rs, http.rs | -- | [~] carried |
| **Biscuit** (attenuable capabilities) | -- | -- | -- | [ ] roadmap |

## Transport

| Standard | What Warden does | Module | Flag |
|---|---|---|---|
| **MCP** (stdio + Streamable-HTTP) | Proxy on the tool boundary; `/healthz`, `/metrics` | http.rs, main.rs | `--http ADDR` |
| **JSON-RPC 2.0** | The MCP wire format | jsonrpc.rs | -- |
| **TLS / mTLS** | Terminated at a front proxy (HTTP transport) | (deployment) | -- |

## Sinks -- where evidence & signals leave the box

Outbound integration is `format x transport x filter x delivery`, configured as
`[[sink]]` entries. Sinks ship a *derived, projected* view; the canonical
tamper-evident chain stays local. See [sink.rs](../src/sink.rs).

| Capability | What Warden does | Module | Config |
|---|---|---|---|
| **OCSF -> SIEM / Security Lake** | Emit decisions as OCSF over file or signed HTTP webhook | sink.rs, ocsf.rs | `format="ocsf"` |
| **CAEP transmitter** (Shared Signals) | Emit signed **SETs** (RFC 8417) -- `session-revoked` for revocations, a Warden event type for risk -- over RFC 8935 push. Warden is both consumer *and producer* of shared signals. | sink.rs `sign_set` | `format="caep"` + `key` |
| **Fail-safe delivery** | Background forwarder tails the audit WAL by offset (at-least-once, retry, replay-safe) -- never touches the action path | [main.rs](../src/main.rs) `forward_sinks` | `delivery="fail-safe"` |
| **High-assurance (blocking)** | The action holds until the evidence is durably acked; unavailable sink => **fail closed** ("no action without a recorded trail") | gateway.rs `ship_blocking` | `delivery="blocking"` |
| **Filters** | `all` / `deny` / `high-risk` / `revocation` | sink.rs `Filter` | `filter=".."` |

Proven: blocking sink unavailable -> action denied (`sink_unavailable`) with the
authorization recorded before the action; CAEP webhook receives a signed
`application/secevent+jwt`; a fail-safe file sink tails OCSF off the hot path.

### Roadmap sinks (format/transport are pluggable)
Iceberg/Parquet (Amazon Security Lake), Sigstore Rekor transparency submission,
OTLP->collector, CloudEvents->Kafka/NATS, in-toto/SLSA attestations, CEF/LEEF
syslog. The `Sink` abstraction is the seam; each is a new `format`/`transport`.

---

## Design stance

Warden **embraces and extends** the standards rather than inventing competing
formats: identity rides OAuth/OIDC + Token-Exchange + DPoP, revocation speaks
CAEP, evidence is OCSF + a transparency-log-style anchor, policy interop is
AuthZEN, multi-hop context is Transaction Tokens, and telemetry is
OpenTelemetry. The published Warden token/audit spec aligns with these so
integration is conformance, not glue.

### Notable remaining edges
- **mTLS-bound tokens** (RFC 8705) as an alternative to DPoP.
- **SD-JWT / Verifiable Credentials + DIDs** for selective disclosure / cross-org identity.
- **Biscuit** for offline-attenuable capability tokens down an agent chain.
- **Live Sigstore/Rekor** submission of anchor checkpoints (format is ready; submission is an external sink).
- **GNAP** (RFC 9635) as a richer grant protocol.
