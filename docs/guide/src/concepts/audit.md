# The audit chain

Warden records **every decision** — allowed, denied, held, approved — to an
append-only JSONL log. It is the agent's *black-box recorder*, and it is
**tamper-evident**: each entry's hash covers its own content **plus the previous
entry's hash**, so altering any past entry breaks the chain from that point on.

```text
entry[n].row_hash = sha256( canonical_json(entry[n] fields) + entry[n-1].row_hash )
```

The hash is computed over a canonical JSON encoding of the accountability-bearing
fields (agent, tool, args, decision, outcome, reason, the accountable human, the
delegation chain, the authorizing token `jti`, the approval reference, …), so
*who was accountable* cannot be rewritten without breaking the chain.

## Verify it

```sh
warden audit tail                 # what agents did, one line per decision
warden audit verify               # prove the record wasn't altered
```

`verify` recomputes the chain and reports the first broken link if any. Try it:
run the demo, edit one line in the log, and re-run `verify` — it is caught.

## Rollback protection: the signed anchor

The hash chain proves no *interior* row changed, but a self-consistent **prefix**
(someone drops the last N rows) still verifies. To detect truncation/rollback,
Warden signs **checkpoints** of the chain head to a separate anchor file:

```sh
warden proxy … --anchor .warden/anchor.jsonl --anchor-key anchor.pem
warden audit verify --anchor .warden/anchor.jsonl --anchor-pub anchor.pub.pem
```

An attacker cannot forge a checkpoint without the private key, and a rollback
that *passes* plain chain verification is caught by the anchor. Ship the anchor
(and the audit log) to **WORM / append-only / offsite** storage, and schedule
`warden audit verify` in your monitoring.

> **Without an anchor**, `warden audit verify` warns that tail truncation is not
> detectable. For high-stakes enforcement, always anchor.

## Data minimisation & redaction

Tool arguments can carry PII and secrets. Warden records a **redacted
projection** of the args (the forwarded call keeps the real args), driven by
regulation profiles:

```sh
warden proxy … --redact gdpr,pci,secrets --redact-scan-values
```

Redaction runs **before** hashing, so the record and its hash cover the redacted
bytes. Both field-name and value-scan detection apply (including PII sent as JSON
numbers).

## Downstream evidence

- **OCSF sink** (`--ocsf FILE`) — SIEM-ready events for each decision.
- **Standards-based sinks** — configurable format × transport × filter ×
  delivery, including a **blocking** high-assurance mode: the evidence must be
  acknowledged *before* the action executes (the fail-closed evidence gate).
- **Signed Event Tokens (SET)** — CAEP-style signed events for cross-system
  propagation.

See [Operating in production](../integrating/production.md) and the
[security reference](../reference/security.md).
