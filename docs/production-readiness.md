# Production-readiness checklist

> Status: tracking. Warden today is a single-node, file-backed MCP stdio MVP.
> This is the gap list to production, tiered by what *blocks* production vs.
> hardening and reach. Check items off as they land.

## P0 -- correctness & security blockers

- [x] **1. Real token verification.** [x] Asymmetric JWT (RS256/ES256/EdDSA) in
  [identity.rs](../src/identity.rs) via `jsonwebtoken`: keys from a JWKS file
  (matched by `kid`) or a PEM public key, issuer allowlist (`--iss`), audience
  (`--aud`), clock-skew leeway (`--leeway`), and an **asymmetric-only algorithm
  allowlist** that blocks the RS256->HS256 confusion downgrade. Dev keyed-digest
  envelope retained as an explicit local-only fallback. Proven by unit tests
  (real ES256 sign/verify, alg-confusion rejection, expiry/actor/aud checks) and
  a CLI smoke test (JWT + JWKS, tamper rejected, fails closed).
  - Remaining sub-piece: **HTTP JWKS fetch + cache + rotation** (today JWKS is
    read from a local file; live fetch needs an HTTP client + TTL cache).
- [x] **2. Holds must not block the proxy.** [x] `Gateway` now uses interior
  mutability and is shared as `Arc<Gateway>`; the proxy spawns a worker thread
  per request and drains them on EOF ([main.rs](../src/main.rs),
  [gateway.rs](../src/gateway.rs)). A held call blocks only its own worker (the
  upstream lock is released during the approval wait); responses correlate by
  JSON-RPC id, so out-of-order replies are fine. Proven: an allowed request
  returns ahead of a concurrently-held one.
  - Follow-up: bounded worker pool (today thread-per-request) + graceful drain
    timeout on shutdown (P1 #8).
- [x] **3. Concurrency-safe audit.** [x] `AuditLog` ([audit.rs](../src/audit.rs))
  now caches the chain head in memory (O(1) appends, no full re-read) behind a
  persistent append handle, and takes an **exclusive advisory file lock**
  (std's native `File::try_lock`) so a second process can't corrupt the chain --
  it's refused with "locked by another writer". In-process, the gateway's
  `Mutex<AuditLog>` serializes worker threads. Proven: 20 concurrent appends ->
  unbroken chain with sequential seqs; a second proxy on the same file is locked
  out without corrupting it.
- [x] **4. Per-action token freshness.** [x] The principal is re-validated on
  every action (`ensure_fresh` in [gateway.rs](../src/gateway.rs)). When the
  token's `exp` has passed, Warden reloads a refreshed token from its source and
  swaps the principal; if it can't, the session is denied ("token expired; no
  longer authorized" -- fail closed). Proven: a 2s token flips allow->deny at
  expiry, and a rotated token file is picked up (audit shows `tok_v1`->`tok_v2`).
  - Remaining sub-piece: token **transport** is still a file path; deciding
    env / MCP `initialize` metadata / per-request transport is open.
- [x] **5. External audit anchor.** [x] Warden signs **checkpoints** of the chain
  head (ES256) to a separate anchor file ([anchor.rs](../src/anchor.rs)); a
  proxy takes `--anchor FILE --anchor-key PEM`, and `audit verify --anchor
  --anchor-pub` checks each checkpoint's signature and that the referenced head
  still matches the chain. Proven: a rollback that *passes* plain chain verify
  is caught by the anchor ("rollback detected"). An attacker can't forge a
  checkpoint without the private key.
  - Remaining sub-piece: ship the anchor file to **WORM/append-only/offsite**
    storage (operational), and support RSA/EdDSA anchor keys (today ES256).
- [x] **6. Approver authentication.** [x] Approvals can be **signed** (ES256,
  `kid` = approver) binding the approver to the action id (itself a hash of
  agent+tool+args) -- [approval_sig.rs](../src/approval_sig.rs). The proxy
  (`--approver-jwks FILE`) honors an approval only if its assertion verifies
  against an allowlisted approver key and is bound to *this* action; otherwise
  it fails closed. `approve --approver-key PEM` signs. Proven: signed approval
  honored, unsigned/forged rejected; replay-to-different-action and
  unknown-approver rejected (unit tests). Legacy unsigned approvals still work
  when no allowlist is configured (demo).

## P1 -- scale & operability

- [x] 7. **Durable budget/run state.** [x] [budget.rs](../src/budget.rs): a
  proxy with `--budget FILE` loads counts at startup and persists on each
  increment, so per-run caps survive restarts (no reset-by-restart bypass).
  In-memory by default (demo). Proven: a `max_per_run=2` cap denies the 3rd call
  across 3 separate proxy processes. (Multi-process *shared* atomic reservation
  is a follow-up; today single-writer per run.)
- [x] 8. **Upstream resilience.** [x] [upstream.rs](../src/upstream.rs):
  per-call **timeout** (`--upstream-timeout`, read in a worker thread bounded by
  `recv_timeout`), **auto-restart** of the child on crash/EOF/timeout, and clean
  JSON-RPC errors to the agent instead of hangs. Workers are joined on EOF
  (graceful drain). Proven: a hung server returns "timed out...restarted" in ~1s;
  a crashed server returns "closed...restarted"; subsequent requests recover.
  - Follow-up: bounded drain *timeout* on shutdown (don't wait forever on a
    stuck worker).
- [x] 9. **Observability.** [x] [obs.rs](../src/obs.rs): per-decision structured
  JSON logs to stderr (`--log-format json`) with tool/decision/outcome/latency/
  accountable/jti, rolling counters by decision and outcome, and a metrics
  snapshot (`--metrics FILE` + a summary line on drain). Proven on a 3-call run.
  - Follow-up: health endpoint + Prometheus exposition come with HTTP transport
    (#10); richer tracing spans optional.
- [~] 10. **Transport + handshake.**
  - [x] **Validated MCP handshake.** [x] The gateway tracks `initialize`;
    `--require-handshake` rejects any `tools/call` that precedes it
    ([gateway.rs](../src/gateway.rs)). Proven: pre-handshake call blocked;
    initialize-then-call succeeds.
  - [x] **HTTP transport.** [x] Hand-rolled MCP Streamable-HTTP (JSON-response
    mode) over `std::net`, thread-per-connection, no new deps
    ([http.rs](../src/http.rs)); `--http ADDR`. Same gateway/identity/policy
    enforcement as stdio; `initialize` returns `Mcp-Session-Id`; adds
    `GET /healthz` and `GET /metrics`. Proven with `curl`: allow/deny, session
    header, health, metrics.
    - Follow-up: server-initiated **SSE streaming** (GET stream) is not
      implemented (request/response only); TLS termination is expected to be
      handled by a front proxy.

## P2 -- completeness & DX

- [x] 11. **Policy engine completeness.** [x] [policy.rs](../src/policy.rs):
  `resource:` namespace (trusted, token-carried `resource_attrs` tied to the
  rule's `require_relation`); **OR/NOT/AND** combinators (`{any=[..]}`,
  `{not=..}`, arrays); `warden policy lint` (unreachable rules, unknown field
  namespaces, zero budgets, `resource:` without a relation -- exits nonzero on
  errors); and `warden policy test --tool .. --args .. [--token ..]` dry-run
  printing decision/trace/reason without executing. Proven by unit tests + CLI.
- [x] 12. **Event-driven revocation.** [x] [revocation.rs](../src/revocation.rs):
  a signed, append-only feed of ES256 revocation events that the proxy tails
  (`--revocations FILE --revocation-pub PEM`) into an in-memory set, checked
  inline (pipeline step 0b) -- revoke by `jti`, `agent`, or `human`, fail closed;
  unsigned events rejected. `warden revoke --jti|--agent|--human --revoke-key`
  appends. Multi-node = instances tail a shared feed. Proven: a running proxy
  denies a call live (no restart) right after a `jti` is revoked.
- [x] 13. **Tests & CI.** [x] [tests/e2e.rs](../tests/e2e.rs): black-box
  integration tests driving the built binary (demo + chain verify, tamper
  detection, `policy lint`, proxy deny path + malformed-input robustness, token
  conformance). `warden token verify` is the conformance checker adapters run
  against. [.github/workflows/ci.yml](../.github/workflows/ci.yml) runs fmt +
  clippy (`-D warnings`) + build + unit/integration tests + a demo smoke. 23
  unit + 5 integration tests green; clippy clean.
  - Follow-up: `cargo-fuzz` parser fuzzing (nightly) beyond the malformed-input
    test; conformance *vectors* for the SDK adapters.
- [x] 14. **Packaging.** [x] Multi-stage [Dockerfile](../Dockerfile) (slim,
  non-root runtime); a `[proxy]` TOML **config file** (`--config`, flags
  override it -- see [warden.proxy.toml](../warden.proxy.toml)); and **SIGHUP**
  live policy reload (Unix). Proven: a config-only proxy run, and an edit-then-
  SIGHUP that flips a live decision allow->deny without restart. Secrets are
  injected as file paths (keys/tokens), mountable as Docker/K8s secrets.
  - Follow-up: env-var secret injection and a published image.

## Hardening review (pre-open-source)

The security-critical paths (identity/crypto, decision pipeline & policy,
parsing/transport, audit integrity) went through an adversarial review. Fixes
landed for: an ungated forward of malformed `tools/call`; a non-injective audit
row hash; JWT `aud`/`iss` not required when configured; an HTTP `Content-Length`
process-abort DoS plus socket timeouts; revocation/freshness not re-checked
after an approval wait; a budget check-then-increment race; a numeric-condition
bypass via string-encoded numbers; redaction skipping numeric leaves; optional
DPoP `iat`; a per-request-identity fallback to the session principal; and
SSRF/DoS hardening of the outbound JWKS/OIDC fetch. Each has a regression test.

**Documented residuals (not blockers; tracked):**
- **Audit rollback needs the anchor.** Plain `warden audit verify` proves no
  *interior* row changed, but a truncated tail (drop the last N rows) still
  verifies; only a signed `--anchor` detects rollback. `verify` now says so.
- **Audit-write availability choice.** A failed audit *write* logs loudly and
  returns a placeholder; the decision still proceeds. The fail-*closed* evidence
  gate is a blocking sink (`ship_blocking`). Use one where "no action without a
  durable record" is required.
- **Approval-assertion replay against an identical action.** A signed approval
  is bound to the action *fingerprint* (agent+tool+args) with no per-instance
  nonce, so a byte-identical future action can be auto-released. Full fix: a
  per-request nonce.
- **Tool matching is exact/case-sensitive** by design; only relevant if an
  upstream resolves tool names case-insensitively.
- **Host/root compromise holding the signing keys** remains out of scope until
  KMS/HSM integration (see SECURITY.md).

## Working order

**All P0, P1, and P2 items complete.** Each is proven by unit/integration tests
and a CLI/HTTP demonstration (see per-item notes); CI enforces fmt + clippy
(`-D warnings`) + tests. Remaining work is the inline follow-up sub-pieces only
(HTTP JWKS fetch, worker pool + drain timeout, token transport, WORM shipping,
RSA/EdDSA anchor keys, multi-process budget reservation, SSE streaming, TLS,
cargo-fuzz, env-var secrets, published image) -- hardening, not new properties.
