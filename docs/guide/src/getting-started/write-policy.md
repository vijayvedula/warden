# Write a policy

A policy is the set of rules Warden evaluates on every `tools/call`. Start
restrictive, allow deliberately.

## A starter policy

```toml
# warden.policy.toml
default = "deny"                 # anything not matched is blocked
require_identity = true          # every call must carry a verified token

# Reads are safe.
[[rules]]
tool = "read_*"
decision = "allow"

# Outbound side effects wait for a human.
[[rules]]
tool = "create_ticket"
decision = "require_approval"
reason = "ticket creation needs human sign-off"

# High-value transfers wait for a human; smaller ones pass.
[[rules]]
tool = "wire_funds"
when = { arg = "amount", op = "gt", value = 1000 }
decision = "require_approval"

# Destructive actions are never allowed unattended.
[[rules]]
tool = "delete_*"
decision = "deny"
reason = "destructive"
```

First matching rule wins; otherwise `default`.

## Add authorization gates

Once your token carries roles/relationships (see the
[identity token](../concepts/identity-token.md)):

```toml
# RBAC — the token must carry this role.
[[rules]]
tool = "read_*"
require_role = "data.reader"
decision = "allow"

# ReBAC — the token must hold `can_read` on the exact table the call targets.
[[rules]]
tool = "query_table"
require_relation = { relation = "can_read", resource_arg = "table" }
decision = "allow"

# ABAC — a condition on a signed token attribute.
[[rules]]
tool = "export_*"
when = { field = "subject:region", op = "eq", value = "EU" }
decision = "allow"
```

## Test before you deploy

```sh
warden policy lint --policy warden.policy.toml          # catch mistakes
warden policy test --policy warden.policy.toml \
  --tool wire_funds --args '{"amount": 5000}'           # dry-run a decision
warden policy test --policy warden.policy.toml \
  --tool query_table --args '{"table":"sales"}' --token .warden/token.json
```

`lint` flags unreachable rules, unknown field namespaces, and zero budgets — wire
it into CI. `test` prints the decision, the trace of which gate decided it, and
the reason, executing nothing.

## Iterate safely in production

- Run **observe-only first**: set permissive decisions and watch the audit trail
  before you enforce.
- Warden **hot-reloads** policy on `SIGHUP` (or `warden pause`/`warden resume`) —
  no restart, no dropped calls.

See the full [policy reference](../reference/policy.md).
