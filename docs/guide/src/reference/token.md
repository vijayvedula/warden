# Token & claims spec

The token is the contract between your platform and Warden. This is its shape.
Warden accepts either a **compact JWT** (production) or a **dev envelope**
(local).

## Claims

```json
{
  "iss": "https://idp.example.com",
  "aud": "warden:prod",
  "exp": 1893456000,
  "nbf": 1893452400,
  "iat": 1893452400,
  "jti": "tok_abc123",

  "sub": "alice@example.com",
  "act": { "sub": "svc-principal", "act": { "sub": "prod-agent" } },

  "roles": ["analyst"],
  "attrs": { "region": "EU", "team": "research" },
  "rel":   [ { "relation": "can_read", "resource": "table:sales" } ],
  "scope": ["query_table", "read_records"],
  "resource_attrs": { "table:sales": { "classification": "public" } },

  "cnf": { "jkt": "<DPoP JWK SHA-256 thumbprint>" }
}
```

| Claim | Required | Meaning |
|-------|----------|---------|
| `sub` | ✅ | Accountable **human**. Empty ⇒ fail closed. |
| `act` | ✅ | Delegation chain; the **deepest `sub` must equal `--agent`**. |
| `aud` | when `--aud` set | Audience; must match. |
| `iss` | when `--iss` set | Issuer; must be in the allowlist. |
| `exp` / `nbf` | `exp` in JWT mode | Validity window (with `--leeway`). |
| `jti` | recommended | Token id; used for revocation and audit. |
| `roles` | — | RBAC roles. |
| `attrs` | — | ABAC attributes (`subject:` conditions). |
| `rel` | — | ReBAC tuples `{relation, resource}`. |
| `scope` | — | Delegated tool grant (scope narrowing). |
| `resource_attrs` | — | Trusted per-resource attributes (`resource:` conditions). |
| `cnf.jkt` | — | DPoP proof-key thumbprint (RFC 7800/9449). |

## Verification rules

- **Algorithm** — asymmetric only (`RS*`, `PS*`, `ES*`, `EdDSA`). HMAC and
  `none` are rejected (blocks the RS256→HS256 downgrade).
- **Key source** — JWKS (by `kid`, file or HTTPS with cache/rotation), OIDC
  discovery, or a PEM public key.
- **Accountability** — non-empty `sub`; the leaf actor of `act` must equal the
  agent on the wire.
- **Freshness** — `exp`/`nbf` with leeway; session tokens are re-validated (and
  refreshed-or-denied) per action.

## Dev envelope (local only)

```json
{
  "claims": { "sub": "alice@example.com", "act": { "sub": "prod-agent" }, "aud": "warden:test" },
  "sig": "<sha256_hex('KEY|' + canonical_json(claims))>"
}
```

Verified with `--token-key KEY`. With no key it's an unsigned dev token
(`signed = false`). **Never** an enforcement mode.

## Produce & verify

Build tokens with the [Python SDK](../integrating/sdk.md) (`TokenBuilder`,
identity adapters, `JwtSigner`), and verify any token the way the proxy does:

```sh
warden token verify --token FILE --agent NAME --aud AUD \
  (--jwks-url URL | --issuer-key PEM | --token-key KEY)
```

The proxy **always** accepts a raw conforming token with no SDK — this spec is
the interface.
