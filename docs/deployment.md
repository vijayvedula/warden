# Warden -- Deployment Guide

How to deploy and run Warden locally, on-prem, on AWS, and on Azure. Warden is
a **single static binary** that sits between an agent and its tool (MCP) server
and enforces every `tools/call`.

---

## 0. Mental model (read this first)

- Warden **spawns one upstream MCP server** as a subprocess (`--upstream "<cmd>"`)
  and governs the `tools/call`s flowing to it. For multiple tool servers, run
  **one Warden per server** (each its own endpoint), or front an aggregating
  MCP server.
- Agents reach Warden two ways:
  - **stdio (sidecar / co-located):** the agent launches `warden proxy ...` as its
    MCP server; Warden launches the real tool server. No network hop.
  - **HTTP (gateway):** `warden proxy --http ADDR ...` listens; agents connect over
    HTTP (MCP Streamable-HTTP). Put a bearer token (`--http-auth-token`) and TLS
    at the edge.
- **Identity is carried:** a Warden instance is launched with the agent's signed
  token (`--token ...`) -- one Warden ~ one agent session (sidecar), verified
  against your IdP's JWKS.
- **Everything is config-or-flags:** `--config warden.proxy.toml` (a `[proxy]`
  table + `[[sink]]` entries); flags override config.

Two topologies:

| | Sidecar (stdio or loopback HTTP) | Gateway (HTTP) |
|---|---|---|
| One Warden per | agent / session | fleet / tool server |
| Network hop | none (loopback) | yes (TLS at edge) |
| Revocation granularity | surgical (one process) | coarser |
| Best for | native & hybrid runtimes | many clients, one tool plane |

---

## 1. Build & install

```sh
# From source (Rust toolchain)
cargo build --release            # -> target/release/warden

# Container image (multi-stage, slim, non-root)
docker build -t warden:latest .
```

Sanity check (no API key, no network):

```sh
warden demo
warden audit verify --audit .warden-demo/audit.jsonl
```

---

## 2. Local

### 2a. As an MCP proxy in front of a tool server

```sh
warden proxy \
  --upstream "python3 examples/echo_mcp_server.py" \
  --agent "dev-agent" \
  --policy warden.policy.toml \
  --audit .warden/audit.jsonl
```

### 2b. With a config file (recommended)

```sh
warden proxy --config warden.proxy.toml
```

```toml
# warden.proxy.toml
[proxy]
upstream = "python3 examples/echo_mcp_server.py"
agent = "dev-agent"
policy = "warden.policy.toml"
log-format = "json"
```

### 2c. HTTP gateway locally

```sh
warden proxy --upstream "python3 examples/echo_mcp_server.py" \
  --policy warden.policy.toml --http 127.0.0.1:8080 \
  --http-auth-token "dev-token"

curl -s localhost:8080/healthz
curl -s -X POST localhost:8080/ -H 'Authorization: Bearer dev-token' \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"."}}}'
```

Operate it: `warden audit tail` / `warden audit verify` / `warden approvals list`
/ `warden approve <id> --by you` / `warden pause` / `warden resume` /
`warden policy lint` / `warden token verify --token t.jwt --aud ...`.

---

## 3. On-Prem

### 3a. Docker (Warden + tool server in one image)

Because Warden spawns the upstream, bake both into one image:

```dockerfile
FROM warden:latest
# add your MCP tool server + its runtime
COPY tools_server.py /srv/tools_server.py
# (install python/node as needed in a derived base)
```

```sh
docker run --rm -p 8080:8080 \
  -v $PWD/keys:/keys:ro -v $PWD/warden.proxy.toml:/cfg/warden.proxy.toml:ro \
  -v warden-audit:/var/warden \
  your-org/warden-tools:latest \
  proxy --config /cfg/warden.proxy.toml --http 0.0.0.0:8080
```

### 3b. systemd (bare VM)

```ini
# /etc/systemd/system/warden.service
[Unit]
Description=Warden action control plane
After=network.target

[Service]
ExecStart=/usr/local/bin/warden proxy --config /etc/warden/warden.proxy.toml --http 127.0.0.1:8080
Restart=on-failure
User=warden
# graceful drain on stop (SIGTERM -> drain -> exit)
KillSignal=SIGTERM
TimeoutStopSec=15
# reload policy without restart
ExecReload=/bin/kill -HUP $MAINPID

[Install]
WantedBy=multi-user.target
```

`systemctl reload warden` hot-reloads policy (SIGHUP); `systemctl stop` triggers
the graceful drain.

### 3c. Kubernetes -- sidecar (one Warden per agent pod)

```yaml
apiVersion: apps/v1
kind: Deployment
metadata: { name: my-agent }
spec:
  replicas: 1
  selector: { matchLabels: { app: my-agent } }
  template:
    metadata: { labels: { app: my-agent } }
    spec:
      containers:
        - name: agent
          image: your-org/agent:latest
          env: [{ name: WARDEN_URL, value: "http://127.0.0.1:8080" }]
        - name: warden                      # sidecar
          image: your-org/warden-tools:latest
          args:
            - "proxy"
            - "--config=/cfg/warden.proxy.toml"
            - "--http=127.0.0.1:8080"        # loopback only
            - "--http-auth-token=$(WARDEN_TOKEN)"
          env:
            - { name: WARDEN_TOKEN, valueFrom: { secretKeyRef: { name: warden, key: http-token } } }
          volumeMounts:
            - { name: cfg, mountPath: /cfg, readOnly: true }
            - { name: keys, mountPath: /keys, readOnly: true }
            - { name: audit, mountPath: /var/warden }
          readinessProbe: { httpGet: { path: /healthz, port: 8080 } }
          livenessProbe:  { httpGet: { path: /healthz, port: 8080 } }
      volumes:
        - { name: cfg, configMap: { name: warden-policy } }
        - { name: keys, secret: { secretName: warden-keys } }
        - { name: audit, emptyDir: {} }      # or a PVC / shipped to WORM
```

The agent talks to Warden on `127.0.0.1:8080`; tools are reached only through
Warden. For a **gateway** instead, make Warden its own `Deployment` + `Service`
and point many agents at it.

### 3d. On-prem evidence & control plane

- **Audit** -> a PVC, then ship to WORM/immutable storage; schedule
  `warden audit verify` (CronJob).
- **Revocation** -> mount a shared `revocations.jsonl` (signed feed); admins
  `warden revoke --jti ... --revoke-key ...`.
- **Keys** -> from your secrets manager/HSM, mounted read-only; never beside the
  audit file.
- **Policy** -> a ConfigMap (GitOps); `kill -HUP` / pause->resume to reload.

---

## 4. AWS

### 4a. ECS (Fargate) -- agent + Warden sidecar

```jsonc
// task definition (excerpt)
{
  "family": "agent-with-warden",
  "containerDefinitions": [
    { "name": "agent", "image": "<ecr>/agent:latest",
      "environment": [{ "name": "WARDEN_URL", "value": "http://localhost:8080" }] },
    { "name": "warden", "image": "<ecr>/warden-tools:latest",
      "command": ["proxy","--config","/cfg/warden.proxy.toml","--http","127.0.0.1:8080"],
      "secrets": [
        { "name": "WARDEN_TOKEN", "valueFrom": "arn:aws:secretsmanager:...:warden/http-token" }
      ],
      "healthCheck": { "command": ["CMD","/usr/local/bin/warden","--help"] } }
  ]
}
```

### 4b. EKS -- same as Sec 3c, with AWS-native plumbing

- **Identity:** the agent's token is minted from **Cognito / STS** (IRSA for the
  pod's service-account -> STS); Warden verifies via the issuer's JWKS:
  `--issuer-url https://cognito-idp.<region>.amazonaws.com/<pool>` (OIDC discovery)
  or `--jwks-url ...`.
- **Secrets/keys:** AWS Secrets Manager / KMS (CSI secrets-store driver) ->
  mounted; signing keys (anchor/approval/txn/sink) from KMS.
- **Evidence sinks** ([[sink]] in config):
  - OCSF -> **Amazon Security Lake** (its native schema is OCSF) or your SIEM.
  - Audit/anchor -> **S3 with Object Lock** (WORM).
  - CAEP SETs -> your IdP / Shared-Signals receiver.
- **Tools the agent acts on:** Bedrock AgentCore Gateway, RDS, internal APIs --
  reached only through Warden's upstream.

```toml
# warden.proxy.toml (AWS)
[proxy]
upstream = "python3 /srv/tools_server.py"
agent = "agent:checkout"
policy = "/cfg/warden.policy.toml"
issuer-url = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_xxx"
aud = "warden:prod"
require-at-jwt = true
http = "127.0.0.1:8080"
log-format = "json"

[[sink]]            # decisions -> Security Lake (OCSF)
name = "security-lake"
format = "ocsf"
transport = "webhook"
endpoint = "https://<collector>/ocsf"
delivery = "fail-safe"
```

### 4c. AWS Lambda / serverless agents
Run Warden as a small **gateway service** (ECS/EKS) the Lambda calls over HTTP;
Lambda is too ephemeral for a sidecar with a durable audit file.

---

## 5. Azure

### 5a. Azure Container Apps -- agent + Warden sidecar

```yaml
# containerapp (excerpt)
properties:
  template:
    containers:
      - name: agent
        image: <acr>.azurecr.io/agent:latest
        env: [{ name: WARDEN_URL, value: "http://localhost:8080" }]
      - name: warden
        image: <acr>.azurecr.io/warden-tools:latest
        args: ["proxy","--config","/cfg/warden.proxy.toml","--http","127.0.0.1:8080"]
        env:
          - name: WARDEN_TOKEN
            secretRef: warden-http-token
        probes:
          - { type: Readiness, httpGet: { path: /healthz, port: 8080 } }
```

### 5b. AKS -- same as Sec 3c, with Azure-native plumbing

- **Identity:** **Microsoft Entra ID** (workload identity) mints the token;
  Warden verifies via Entra's JWKS (`--issuer-url https://login.microsoftonline.com/<tenant>/v2.0`).
- **Secrets/keys:** **Azure Key Vault** (CSI driver) -> signing keys.
- **Evidence sinks:** OCSF -> **Microsoft Sentinel**; audit/anchor -> **Azure Blob
  with immutable (WORM) policy**; CAEP SETs -> Entra / SSF receiver.

```toml
[proxy]
issuer-url = "https://login.microsoftonline.com/<tenant>/v2.0"
aud = "api://warden-prod"
# ... as above
```

---

## 6. Production checklist (every environment)

- **TLS/mTLS** at the edge for HTTP; bind to loopback in sidecar mode.
- **`--http-auth-token`** on the HTTP surface; `/healthz` stays open for probes.
- **Verify real tokens** (`--issuer-url`/`--jwks-url`, `--aud`, `--require-at-jwt`);
  not the dev envelope. Sender-constrain with **DPoP** on HTTP.
- **Keys in KMS/Key Vault/Secrets**, mounted read-only, never beside the audit.
- **Audit -> WORM** + scheduled `audit verify` (+ anchor verify); **sinks -> SIEM**.
- **Revocation feed** mounted/replicated; **graceful drain** on SIGTERM
  (`--drain-timeout`); **policy reload** via SIGHUP.
- **Redaction** (`--redact gdpr,pci,secrets`) for recorded/exported data.
- See [threat-model.md](threat-model.md), [SECURITY.md](../SECURITY.md), and
  [production-readiness.md](production-readiness.md).

---

## 7. Reference -- common flags

| Concern | Flags |
|---|---|
| Transport | `--http ADDR` / `--http-auth-token` / (else stdio) / `--drain-timeout` |
| Identity | `--token` / `--issuer-url` / `--jwks-url` / `--jwks` / `--issuer-key` / `--aud` / `--iss` / `--require-at-jwt` / `--leeway` |
| Policy | `--policy` / `policy lint` / `policy test` / SIGHUP reload |
| Approvals | `--approver-jwks` / `approve --approver-key` |
| Audit/evidence | `--audit` / `--anchor`/`--anchor-key` / `--ocsf` / `[[sink]]` |
| Revocation | `--revocations`/`--revocation-pub` / `warden revoke` |
| A2A | `--txn-key` / `--txn-verify-key` |
| Budgets | `--budget` |
| Privacy | `--redact` / `--redact-fields` / `--redact-scan-values` |
| Ops | `--log-format json` / `--metrics` / `--control` (pause/resume) |
