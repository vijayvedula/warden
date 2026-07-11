# Policy model

A policy is a TOML file. Warden evaluates each `tools/call` against it:
**the first matching rule wins**; if none match, the `default` applies.

```toml
default = "deny"                # deny anything not explicitly allowed
require_identity = true          # fail closed if a call arrives with no verified token

[[rules]]
tool = "read_*"                  # wildcard tool match
decision = "allow"

[[rules]]
tool = "wire_funds"
when = { arg = "amount", op = "gt", value = 1000 }   # condition on a tool arg
decision = "require_approval"
reason = "large transfers need a human"

[[rules]]
tool = "delete_database"
decision = "deny"

[[rules]]
tool = "write_file"
decision = "allow"
max_per_run = 20                 # per-run budget
```

## Decisions

- <code class="allow">allow</code> — forward to the upstream.
- <code class="deny">deny</code> — block; the agent gets a clean tool error.
- <code class="hold">require_approval</code> — hold for a human
  (`warden approve`/`warden deny`).

## Matching & conditions

- **Tool match** — exact, or a trailing `*` wildcard (`admin_*`), or `*` for all.
  Matching is case-exact.
- **`when` conditions** — on a tool **arg** (`{ arg = "amount", op = "gt", value = 1000 }`)
  or a trusted **subject/resource/env** field
  (`{ field = "subject:team", op = "eq", value = "research" }`). Operators:
  `gt`, `lt`, `eq`, `contains`. Numeric operators accept a number sent as a
  string. Combine with `{ any = [...] }` (OR), `{ not = ... }` (NOT), and arrays
  (AND). A rule whose `when` doesn't match **falls through** to the next rule —
  which is what lets threshold rules (`amount < X` allow vs `amount ≥ X` hold)
  compose.

## Identity gates (require a verified token)

| Field | Gate |
|-------|------|
| `require_identity = true` | deny any call without a verified, accountable token (RBAC/ABAC/ReBAC below all imply this) |
| `require_role = "analyst"` | the token must carry this role (**RBAC**) |
| `require_relation = { relation = "can_read", resource_arg = "table" }` | the token must hold `can_read@<value of the "table" arg>` (**ReBAC**) |
| `when { field = "subject:region", … }` | condition on a signed token attribute (**ABAC**) |

An authenticated agent is also **scope-narrowed**: it may only call tools present
in the token's `scope`, regardless of the rules.

## Budgets

`max_per_run = N` caps how many times a tool may run in a "run." The count is
reserved **atomically** at forward time, so concurrent calls can't overshoot.
With `--budget FILE` the count is durable across restarts (no reset-by-restart
bypass); in-memory otherwise.

## Author it safely

- `warden policy lint` — static checks: unreachable rules, unknown field
  namespaces, zero budgets, `resource:` without a relation. Exits non-zero on
  errors — run it in CI.
- `warden policy test --tool NAME --args JSON [--token FILE]` — dry-run a call
  and print the decision, trace, and reason **without executing** anything.

See the full [policy reference](../reference/policy.md) and
[Write a policy](../getting-started/write-policy.md).
