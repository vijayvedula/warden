# The identity token

Warden's identity boundary is a **single signed token** that says *who an agent
acts for*. This token is the **only coupling point** between Warden and your
platform — everything else (role expansion, relationship resolution, on-behalf-of
exchange) stays on the platform side, where it already lives. Warden verifies the
token and trusts its claims.

## Delegation semantics (RFC 8693)

The token uses OAuth token-exchange delegation:

- **`sub`** — the **accountable party**, a *human*. Empty ⇒ no accountability ⇒
  Warden fails closed (in identity-required mode).
- **`act`** — the **acting chain**, nested from the outermost service down to the
  leaf agent: `human → [service] → agent`. The **leaf actor must match** the
  agent Warden is running as (`--agent`), or the call is denied.

```json
{
  "sub": "alice@example.com",
  "act": { "sub": "svc-principal", "act": { "sub": "prod-agent" } }
}
```

This encodes "**alice**, through the **svc-principal**, is acting via the
**prod-agent**." The audit chain records that full line of accountability.

## Authorization claims

The token also carries the authorization facts Warden's policy consumes —
trusted because the token is signed:

| Claim | Meaning | Policy use |
|-------|---------|-----------|
| `roles` | RBAC roles/groups | `require_role` |
| `attrs` | ABAC attributes | `when { field = "subject:…" }` |
| `rel` | ReBAC relationship tuples `{relation, resource}` | `require_relation` |
| `scope` | the agent's delegated tool grant | scope narrowing (an agent may only call tools in scope) |
| `resource_attrs` | trusted per-resource attributes | `when { field = "resource:…" }` |
| `cnf.jkt` | DPoP proof-key thumbprint (RFC 7800/9449) | sender-constraint on HTTP |

## Verification modes

- **JWT (production)** — a compact JWT verified against an asymmetric key from a
  **JWKS** (by `kid`, fetchable over HTTPS with caching/rotation) or a **PEM**
  public key. The algorithm is restricted to **asymmetric families only**, which
  blocks the classic RS256→HS256 confusion downgrade. `aud` and `iss` are
  *required* when you configure `--aud`/`--iss`. Selected with `--jwks`,
  `--jwks-url`, `--issuer-url` (OIDC discovery), or `--issuer-key`.
- **Dev envelope** — a `{ "claims": {…}, "sig": "<hex>" }` file with an optional
  keyed-digest signature, for local/demo use only (`--token-key`). Never an
  enforcement mode.

## Where the token comes from

You don't hand-write tokens in production — a platform **identity adapter** mints
one from your native credential (STS session, Databricks OBO, Google workload
identity, Entra OBO). The adapter shapes claims and asks the *platform issuer* to
sign; it never signs authority itself. See [The integration
model](../integrating/model.md) and the [Python SDK](../integrating/sdk.md).

> **The escape hatch:** Warden always accepts a raw conforming token with no SDK
> at all. Adoption is never coupled to a client library — the token spec is the
> contract. See the [token & claims reference](../reference/token.md).
