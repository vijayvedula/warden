# Policy reference

A policy is TOML. Top-level keys plus an ordered list of `[[rules]]`. The **first
matching rule wins**; otherwise `default`.

## Top level

| Key | Type | Meaning |
|-----|------|---------|
| `default` | `"allow"` \| `"deny"` \| `"require_approval"` | Decision when no rule matches. |
| `require_identity` | bool | Deny any call without a verified, accountable token. |

## A rule

```toml
[[rules]]
tool = "wire_funds"                                  # exact, prefix* , or *
decision = "require_approval"                        # allow | deny | require_approval
reason = "large transfers need a human"              # recorded in the audit
require_role = "finance.approver"                    # RBAC gate
require_relation = { relation = "owns", resource_arg = "account" }  # ReBAC gate
when = { arg = "amount", op = "gt", value = 1000 }   # condition (see below)
max_per_run = 5                                       # per-run budget
```

| Field | Meaning |
|-------|---------|
| `tool` | Match: exact name, `prefix*` wildcard, or `*` (all). Case-exact. |
| `decision` | `allow` / `deny` / `require_approval`. |
| `reason` | Human-readable, recorded in the audit entry. |
| `require_role` | Token must carry this role (implies `require_identity`). |
| `require_relation` | Token must hold `relation@<value of resource_arg>`. |
| `when` | Condition tree that must hold for the rule to apply. |
| `max_per_run` | Cap on invocations per run (reserved atomically). |

## Conditions (`when`)

**Leaf condition:**

```toml
when = { arg = "amount", op = "gt", value = 1000 }              # a tool argument
when = { field = "subject:region", op = "eq", value = "EU" }    # a signed token attr
when = { field = "resource:classification", op = "eq", value = "public" }
when = { field = "env:hour", op = "lt", value = 18 }
```

- **Namespaces:** `arg:` (tool args — attacker-influenced), `subject:` (trusted
  token `attrs`), `resource:` (trusted token `resource_attrs`, tied to the rule's
  `require_relation`), `env:` (Warden environment).
- **Operators:** `gt`, `lt`, `eq`, `contains`. Numeric operators accept a number
  sent as a string.

**Combinators:**

```toml
when = { any = [ {arg="a",op="eq",value=1}, {arg="b",op="eq",value=2} ] }   # OR
when = { not = { arg = "dry_run", op = "eq", value = true } }               # NOT
when = [ {arg="a",op="gt",value=0}, {field="subject:role",op="eq",value="x"} ]  # AND
```

## Evaluation order

1. `require_identity` / scope narrowing (authenticated agents may only call tools
   in `scope`).
2. Rules in order: `tool` match → `when` selects (non-match **falls through**) →
   `require_role` / `require_relation` gates → `max_per_run` → the rule's
   `decision`.
3. Otherwise `default`.

A `when` that doesn't match falls through to the next rule — this is what lets
threshold pairs compose (`amount < X` → allow, else → `require_approval`).

## Validate

```sh
warden policy lint --policy FILE     # unreachable rules, unknown namespaces, zero budgets
warden policy test --policy FILE --tool NAME --args JSON [--token FILE]
```

See [warden.policy.toml](https://github.com/vijayvedula/warden/blob/main/warden.policy.toml)
for a worked example and the per-provider policies under
[examples/](https://github.com/vijayvedula/warden/tree/main/examples).
