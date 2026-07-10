# Warden and the Twelve-Factor App

Warden is designed to run as a well-behaved cloud-native process — a sidecar or
gateway you can schedule, scale, and dispose of like any other stateless
service. This document maps each of the [twelve factors](https://12factor.net)
to how Warden is built and operated, and how to stay conformant when you deploy
it.

| # | Factor | How Warden conforms |
|---|--------|---------------------|
| I | **Codebase** | One tracked repository, many deploys. The same `warden` binary runs in dev, staging, and prod; only config differs. |
| II | **Dependencies** | Explicitly declared and locked: `Cargo.toml` + `Cargo.lock` for the core; `pyproject.toml` for the SDK. No reliance on system-wide packages; the container image vendors everything. |
| III | **Config** | Every `warden proxy` option is settable from the environment as `WARDEN_*` (see [`.env.example`](../.env.example)). Precedence: CLI flag › `WARDEN_*` env › `--config` TOML › default. No credentials or environment names are baked into the build. |
| IV | **Backing services** | The audit sink, approval store, JWKS/OIDC issuer, OCSF/SIEM sink, and anchor key are all attached resources referenced by config (`WARDEN_AUDIT`, `WARDEN_JWKS_URL`, `WARDEN_OCSF`, `WARDEN_ANCHOR_KEY`, …). Swapping a local file sink for a network SIEM is a config change, not a code change. |
| V | **Build, release, run** | Strict separation. `cargo build --release` (build) produces an immutable artifact; a tagged release pins config + binary; `warden proxy` (run) never mutates the build. See [`Dockerfile`](../Dockerfile) and the release workflow. |
| VI | **Processes** | Warden runs as one or more stateless processes. All durable state lives in attached backing services (the audit log, approval queue, budget file), never in process memory across restarts. |
| VII | **Port binding** | In gateway mode Warden binds a port and speaks MCP Streamable-HTTP directly (`WARDEN_HTTP=0.0.0.0:8080`) — it is a self-contained service, not something injected into a runtime server. Stdio mode is used for the sidecar-per-agent pattern. |
| VIII | **Concurrency** | Scale out by the process model: one Warden per agent session (sidecar) or a horizontally-scaled pool behind the HTTP gateway. Each request is handled on its own worker; a held approval blocks only its own request, not the process. |
| IX | **Disposability** | Fast startup and graceful shutdown. `SIGTERM`/`SIGINT` stop accepting new calls and **drain in-flight** ones (`WARDEN_DRAIN_TIMEOUT`), then sign a final audit checkpoint. `SIGHUP` hot-reloads policy without a restart. Robust against sudden death: the audit log is an append-only WAL. |
| X | **Dev/prod parity** | The same binary and container run everywhere; the demo path (`warden demo`) and production path share the identical decision pipeline. Differences are confined to config (identity keys, sinks, transport). |
| XI | **Logs** | Logs are an event stream written to stdout/stderr, never to managed log files. `WARDEN_LOG_FORMAT=json` emits structured decision logs for the platform to route. The tamper-evident **audit chain** is a separate, deliberate backing service (evidence), distinct from operational logs. |
| XII | **Admin processes** | One-off admin tasks run as the same binary against the same config: `warden audit verify`, `warden approvals list`, `warden approve/deny`, `warden revoke`, `warden policy lint/test`. No separate admin console with divergent code. |

## Operating notes

- **Secrets** (signing keys, HTTP auth tokens) are injected as attached
  resources — mount them from your platform's secret store and point the
  matching `WARDEN_*` var at the path. Never bake keys into the image or commit
  a real `.env`.
- **Statelessness caveat:** the audit log, approval queue, and durable budget
  are *intentionally* persistent — they are backing services (factor IV), not
  in-process state (factor VI). Put them on a durable volume or ship them to a
  WORM/SIEM sink.
- **Revocation & reload** (factor IX): prefer the sidecar-per-agent topology so
  a pause/reload is surgical to one process. See
  [platform-integration.md](platform-integration.md) for the trade-off against a
  shared gateway.
