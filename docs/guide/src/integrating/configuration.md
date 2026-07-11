# Configuration (12-factor)

Warden follows the [twelve-factor](https://12factor.net) methodology so the same
build runs unchanged across dev, staging, and prod — only its **config** differs.

## Three config channels, in precedence order

1. **CLI flags** — `warden proxy --upstream "…" --agent prod-agent …`
2. **`WARDEN_*` environment variables** — every flag is settable from the
   environment (factor III). The name is the flag upper-cased with dashes as
   underscores: `--jwks-url` → `WARDEN_JWKS_URL`.
3. **`[proxy]` TOML config file** — `--config warden.proxy.toml`.

Flag ▸ env ▸ config ▸ built-in default. So:

```sh
# identical behaviour, three ways:
warden proxy --upstream "python3 tools.py" --agent prod-agent
WARDEN_UPSTREAM="python3 tools.py" WARDEN_AGENT=prod-agent warden proxy
warden proxy --config warden.proxy.toml
```

Copy [`.env.example`](https://github.com/vijayvedula/warden/blob/main/.env.example)
to `.env` and edit. **Never commit a real `.env`** — it's gitignored.

## Common variables

```sh
WARDEN_UPSTREAM="python3 tools_server.py"   # the real MCP tool server to front
WARDEN_AGENT=prod-agent
WARDEN_POLICY=warden.policy.toml
WARDEN_AUDIT=.warden/audit.jsonl            # backing service (factor IV)
WARDEN_JWKS_URL=https://idp/.well-known/jwks.json
WARDEN_AUD=warden:prod
WARDEN_HTTP=0.0.0.0:8080                     # port binding (factor VII); omit for stdio
WARDEN_LOG_FORMAT=json                       # logs as an event stream (factor XI)
WARDEN_DRAIN_TIMEOUT=10                       # graceful drain (factor IX)
```

## Backing services & secrets

The audit sink, approval store, JWKS/OIDC issuer, OCSF/SIEM sink, and anchor key
are **attached resources** referenced by config — swap a local file sink for a
network SIEM with a config change, not a code change. Inject secrets (signing
keys, HTTP auth tokens) as file paths mounted from your platform's secret store;
never bake keys into the image.

## Twelve factors, mapped

Each factor and how Warden conforms is documented in
[docs/twelve-factor.md](https://github.com/vijayvedula/warden/blob/main/docs/twelve-factor.md)
— codebase, dependencies, config, backing services, build/release/run,
processes, port binding, concurrency, disposability, dev/prod parity, logs, and
admin processes (`warden audit verify`, `warden policy lint`, `warden revoke`).

Next: [Operating in production](./production.md).
