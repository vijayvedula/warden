# Quickstart

The fastest way to see Warden work — no API key, no external server.

## 1. The self-contained demo

```sh
cargo build
./target/debug/warden demo
```

The demo drives a simulated agent through every decision path —
<code class="allow">allow</code>, a per-run <code class="hold">budget</code>,
<code class="deny">deny</code>, and a <code class="hold">hold-for-approval</code>
(both approved *and* denied) — then prints the audit trail and verifies the hash
chain.

## 2. Prove the record is tamper-evident

```sh
warden audit tail   --audit .warden-demo/audit.jsonl   # what the agent did
warden audit verify --audit .warden-demo/audit.jsonl   # prove it wasn't altered
```

Now edit any single line in `.warden-demo/audit.jsonl` and re-run `verify` — the
tamper is caught with the exact sequence number.

## 3. Dry-run a policy decision

You can ask Warden what it *would* decide, without running an agent:

```sh
warden policy test --policy warden.policy.toml \
  --tool wire_funds --args '{"amount": 5000}'
# -> decision, trace, and reason, nothing executed
```

## 4. Front a real tool server

Point an MCP client at Warden instead of the tool server; Warden launches the
real server as its upstream:

```sh
warden proxy \
  --upstream "python3 examples/echo_mcp_server.py" \
  --agent prod-agent \
  --policy warden.policy.toml
```

Allowed calls forward; denied calls are blocked before they reach the upstream;
held calls wait for `warden approve`/`warden deny`. Everything is appended to
`.warden/audit.jsonl`.

## Next

- [Govern your first agent](./first-agent.md) — wire Warden into a real agent
  framework.
- Jump to your [provider guide](../providers/index.md) for an end-to-end,
  platform-specific walkthrough.
