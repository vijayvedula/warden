# Azure AI Foundry Agent Service + Warden -- identity & audit example (Entra ID)

Warden sits as the **MCP proxy in front of the Azure AI Foundry Agent Service's
tool servers**. Microsoft Entra ID mints the credential; every `tools/call` is
gated against policy and recorded in a tamper-evident audit chain tied to a named
Entra principal.

```
Foundry agent --(MCP)--> Warden --(MCP, subprocess)--> tool servers
                          | verify Entra token / policy / hold / audit
```

## Identity: the OAuth 2.0 on-behalf-of (OBO) flow

The agent runs under a **managed identity** (or app registration) and acts **on
behalf of** a signed-in user via the Entra ID OBO flow. That produces Warden's
delegation chain:

| Warden claim | Azure / Entra source |
|---|---|
| `sub` (accountable human) | the signed-in user -- Entra `oid` / `upn` |
| `act` (delegation chain) | user -> **managed identity** (middle) -> agent (leaf) |
| `roles` (RBAC) | Entra **app roles** / group claims |
| `attrs` (ABAC) | directory / resource attributes |
| `rel` (ReBAC) | **Azure RBAC** role assignments scoped to a resource (relation = `role.lower()`) |
| `scope` (agent grant) | delegated OAuth scopes on the OBO token |

The `warden_sdk` adapter `azure.from_entra_obo(...)` is a pure claims mapping --
it shapes these claims but never signs. In production the **Entra ID issuer signs**
the JWT; Warden verifies it. This is the same **token-as-interface** pattern the
platform-integration doc spells out for Databricks, Google, and AWS
([../../docs/platform-integration.md](../../docs/platform-integration.md)) --
Azure follows it identically, just with Entra ID / managed identity / Azure RBAC
as the four sources (issuer, on-behalf-of, attributes, and MCP transport).

**What Warden adds** on top of Entra + Azure RBAC (which already govern *access*):
the **human pre-authorization hold** (`require_approval`) and a **tamper-evident,
per-action record** that ties each tool call to a named Entra principal.

## 1. Mint the token

```sh
python mint_token.py alice@contoso.com
# wrote .warden/token.json  (sub=alice@contoso.com, agent=prod-agent, aud=warden:azure)
```

This writes a **dev envelope** (HMAC, shared secret) so the example runs offline.
See "Production" below for the real Entra-signed path.

## 2. Run Warden as the MCP proxy

Point the Foundry agent's MCP client at `warden proxy ...` instead of the tool
server. In Python you wire it via `ProxyConfig`:

```python
from warden_sdk import ProxyConfig
cfg = ProxyConfig(
    upstream="python3 tools_server.py",
    agent="prod-agent",
    token=".warden/token.json",
    audience="warden:azure",
)
```

Warden verifies the token, evaluates [`warden.policy.toml`](warden.policy.toml)
on every `tools/call` (reads need the `Analyst` app role; `query_reports` needs
an Azure RBAC `reader` relation to the resource it targets; `delete_*` is denied),
holds calls marked `require_approval`, and appends each decision to the audit chain.

## 3. Verify the audit

```sh
warden token verify --token .warden/token.json \
  --agent prod-agent --aud warden:azure --token-key dev-secret   # -> token OK

warden audit tail   --audit .warden/audit.jsonl   # each call, allowed/blocked, by whom
warden audit verify --audit .warden/audit.jsonl   # prove the record is untampered
```

## Production

Do **not** sign in the mint script. Have Entra ID / your IdP issue the JWT from
the OBO exchange and let Warden verify it:

```python
from warden_sdk import JwtSigner
jwt = tok.to_jwt(JwtSigner.from_file("issuer.pem", "ES256", "k1"), at_jwt=True)
```

Launch Warden with `--jwks-url <entra-jwks>` / `--aud warden:azure` so every
action ties to a verified, named human. Add `--anchor`/`--anchor-key` for
rollback-proof audit and `--ocsf` for SIEM export.

## See also

- [`../../sdk/python/`](../../sdk/python/) -- the `warden_sdk` package and the
  `azure` identity adapter.
- [`../../docs/platform-integration.md`](../../docs/platform-integration.md) --
  the token-as-interface integration pattern (Databricks / Google / AWS; Azure
  is identical).
