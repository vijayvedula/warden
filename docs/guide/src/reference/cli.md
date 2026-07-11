# CLI reference

Run `warden --help` for the authoritative list. Options resolve **flag ▸
`WARDEN_*` env ▸ `--config` TOML ▸ default** (see
[Configuration](../integrating/configuration.md)).

## Commands

| Command | Purpose |
|---------|---------|
| `warden demo` | Self-contained walkthrough (no API key, no external server). |
| `warden proxy …` | Run as an MCP proxy (stdio, or HTTP with `--http`). |
| `warden approvals list` | List pending held actions. |
| `warden approve <id> [--by WHO] [--approver-key PEM]` | Release a held action (signs a per-action assertion if a key is given). |
| `warden deny <id> [--by WHO]` | Deny a held action. |
| `warden pause` / `warden resume` | Stop/resume forwarding at Warden; resume reloads policy. |
| `warden revoke (--jti X \| --agent Y \| --human Z) --revoke-key PEM` | Append a signed revocation event. |
| `warden token verify --token FILE …` | Verify a token the way the proxy would (conformance check). |
| `warden audit tail` | Show the audit trail. |
| `warden audit verify [--anchor FILE --anchor-pub PEM]` | Verify the chain (and signed checkpoints). |
| `warden policy show \| lint \| test` | Inspect, statically check, or dry-run a policy. |

## `warden proxy` — key flags

**Core**

| Flag | Meaning |
|------|---------|
| `--upstream "<cmd>"` | The real MCP tool server to launch and front (required). |
| `--agent NAME` | This agent's wire identity (must match the token's leaf actor). |
| `--policy FILE` | Policy file (default `warden.policy.toml`). |
| `--config FILE` | A `[proxy]` TOML table; flags override it. |
| `--http ADDR` | Serve MCP Streamable-HTTP instead of stdio. |
| `--log-format json` | Structured decision logs to stderr. |
| `--metrics FILE` | Write a metrics snapshot on drain. |
| `--drain-timeout SECS` | Bound the graceful-shutdown drain. |

**Identity**

| Flag | Meaning |
|------|---------|
| `--token FILE` | Session delegation token (one principal for the process). |
| `--request-identity` | Per-request bearer identity (shared gateway). Mutually exclusive with `--token`. |
| `--aud AUD` / `--iss ISS` | Required audience / issuer allowlist (comma-separated). |
| `--jwks FILE` / `--jwks-url URL` / `--issuer-url URL` | JWKS by file, over HTTPS, or via OIDC discovery. |
| `--issuer-key PEM` | A single PEM public key (instead of JWKS). |
| `--token-key KEY` | Dev-envelope keyed digest (local only). |
| `--leeway SECS` | Clock-skew tolerance. |
| `--require-at-jwt` | Require `typ: at+jwt` (RFC 9068). |

**Evidence & control**

| Flag | Meaning |
|------|---------|
| `--audit FILE` / `--approvals FILE` | Audit log / approval queue paths. |
| `--anchor FILE --anchor-key PEM [--anchor-interval N]` | Sign chain-head checkpoints. |
| `--ocsf FILE` | OCSF event sink (SIEM). |
| `--redact PROFILES [--redact-scan-values]` | PII/secret redaction (gdpr/hipaa/pci/secrets). |
| `--budget FILE` | Durable per-run budget counts. |
| `--http-auth-token TOKEN` | Require a bearer on the HTTP surface. |
| `--approver-jwks FILE` | Require signed approvals from an allowlisted key set. |
| `--revocations FILE --revocation-pub PEM` | Subscribe to a signed revocation feed. |
| `--control FILE` | Enable the admin pause/resume control plane. |
| `--require-handshake` | Reject any `tools/call` before MCP `initialize`. |
| `--upstream-timeout SECS` | Per-call upstream timeout (auto-restart on hang/crash). |

## `warden token verify`

```sh
warden token verify --token FILE --agent NAME [--aud AUD] [--iss ISS] \
  (--jwks FILE | --jwks-url URL | --issuer-key PEM | --token-key KEY) [--require-at-jwt]
```

Prints the accountable subject, the delegation chain, roles, scope, and
relationships if the token verifies; exits non-zero otherwise. This is the check
SDK adapters run against.

## `warden policy`

```sh
warden policy show  --policy FILE
warden policy lint  --policy FILE                      # exits non-zero on errors
warden policy test  --policy FILE --tool NAME [--args JSON] [--token FILE …]
```
