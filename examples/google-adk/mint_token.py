#!/usr/bin/env python3
"""Mint a Warden identity token from a Google workload-identity context.

In production, none of these values are hand-written: they come from Google
IAM. The agent runs as a **service account** (or a workload-identity binding);
the accountable human is the OIDC ``sub`` / domain-wide-delegation subject that
initiated the session. IAM role bindings become RBAC roles, IAM **conditions**
become ABAC ``attrs``, resource-level IAM bindings become ReBAC relationships,
and the agent card's A2A capabilities become the granted ``scope``. The adapter
only *shapes* these claims -- it never signs authority. Here we emit an unsigned
dev envelope so the example runs offline; see README.md for issuing a real,
IAM/IdP-signed JWT.

Run:  python mint_token.py [user_email]
"""
from __future__ import annotations

import os
import sys

from warden_sdk.adapters import google

AGENT = "prod-agent"
AUDIENCE = "warden:google"
TOKEN_PATH = ".warden/token.json"
DEV_KEY = "dev-secret"


def main() -> None:
    user = sys.argv[1] if len(sys.argv) > 1 else "alice@example.com"

    # A realistic Vertex AI Agent Engine / ADK workload-identity context.
    # In production this dict is assembled from the service account's IAM
    # bindings and conditions, plus the agent card's declared capabilities.
    context = {
        "user": user,  # OIDC sub / DWD subject -> accountable human (sub)
        "service_account": "prod-agent@my-proj.iam.gserviceaccount.com",  # -> act hop
        "iam_roles": ["roles/bigquery.dataViewer"],  # -> roles (RBAC)
        "iam_conditions": {"resource.type": "bigquery"},  # IAM condition -> attrs (ABAC)
        "a2a_capabilities": ["query_dataset"],  # agent-card capabilities -> scope
        "resource_bindings": [  # resource-level IAM -> rel (ReBAC)
            {"relation": "dataViewer", "resource": "dataset:analytics"},
        ],
    }

    tok = google.from_workload_identity(context, agent=AGENT, audience=AUDIENCE)

    os.makedirs(os.path.dirname(TOKEN_PATH), exist_ok=True)
    tok.write_dev_envelope(TOKEN_PATH, key=DEV_KEY)

    print(f"wrote {TOKEN_PATH}")
    print(f"  sub (accountable human): {user}")
    print(f"  agent (act leaf):        {AGENT}")
    print()
    print("verify it:")
    print(
        f"  warden token verify --token {TOKEN_PATH} "
        f"--agent {AGENT} --aud {AUDIENCE} --token-key {DEV_KEY}"
    )


if __name__ == "__main__":
    main()
