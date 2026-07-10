#!/usr/bin/env python3
"""Mint a Warden delegation token from a Databricks on-behalf-of-user context.

In production these values are not hard-coded: they come straight from the
Databricks runtime. The agent runs as a **service principal** using
**on-behalf-of-user (OBO)** auth, so Databricks hands you the accountable human
(the OBO ``user``), the service principal, the user's **Unity Catalog** group
membership, and the workspace/catalog context. Unity Catalog also tells you
which **grants** the user holds on which securables. The databricks adapter
shapes all of that into Warden's canonical claims:

    OBO user             -> sub    (the accountable human)
    service principal    -> act    (middle acting hop; agent is the leaf)
    UC group membership  -> roles  (RBAC)
    workspace / catalog  -> attrs  (ABAC)
    UC grants            -> rel    (ReBAC; relation = privilege.lower())
    registered UC funcs  -> scope  (what the agent is allowed to invoke)

The adapter only *shapes* claims — it never signs authority. This script writes
a **dev envelope** (symmetric ``dev-secret`` key) for local runs. In production
you sign a real JWT with the Databricks token issuer / your KMS instead; see the
README (the no-forged-authority rule).

Run:
    python mint_token.py [user_email]
"""

from __future__ import annotations

import os
import sys

from warden_sdk.adapters import databricks

AGENT = "prod-agent"
AUDIENCE = "warden:databricks"
TOKEN_PATH = ".warden/token.json"
DEV_KEY = "dev-secret"


def main() -> None:
    user = sys.argv[1] if len(sys.argv) > 1 else "alice@example.com"

    # In production this dict is populated from the Databricks OBO identity and
    # Unity Catalog metadata available in the agent's serving environment.
    obo_context = {
        "user": user,                              # OBO user -> accountable sub
        "service_principal": "sp-agent-runtime",   # -> middle act hop
        "uc_groups": ["analysts"],                 # UC groups -> roles (RBAC)
        "workspace": "ws-123",                     # -> attrs (ABAC)
        "catalog": "main",                         # -> attrs (ABAC)
        "uc_grants": [                             # UC grants -> rel (ReBAC)
            {"privilege": "SELECT", "securable": "table:main.sales"},
        ],
        "tools": ["read_table", "query_table"],    # registered UC funcs -> scope
    }

    tok = databricks.from_obo(obo_context, agent=AGENT, audience=AUDIENCE)

    os.makedirs(os.path.dirname(TOKEN_PATH), exist_ok=True)
    tok.write_dev_envelope(TOKEN_PATH, key=DEV_KEY)

    print(f"Wrote dev token for {user} -> {TOKEN_PATH}")
    print("Verify it (leaf actor, audience, and dev signature) with:")
    print(
        f"  warden token verify --token {TOKEN_PATH} "
        f"--agent {AGENT} --aud {AUDIENCE} --token-key {DEV_KEY}"
    )


if __name__ == "__main__":
    main()
