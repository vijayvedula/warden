#!/usr/bin/env python3
"""Mint a Warden identity token from a Microsoft Entra ID on-behalf-of context.

In production these values are NOT hand-written -- they come from Microsoft
Entra ID and the OAuth 2.0 on-behalf-of (OBO) flow that the Azure AI Foundry
Agent Service performs when an agent acts for a signed-in user:

    - ``user``             the signed-in human (Entra ``oid`` / ``upn``)     -> accountable ``sub``
    - ``managed_identity`` the agent's managed identity / app registration   -> middle ``act`` hop
    - ``app_roles``        Entra app roles / group claims                     -> ``roles`` (RBAC)
    - ``attributes``       directory / resource attributes                   -> ``attrs`` (ABAC)
    - ``scopes``           delegated OAuth scopes on the OBO token           -> ``scope`` (grant)
    - ``role_assignments`` Azure RBAC role assignments scoped to a resource  -> ``rel`` (ReBAC)

The leaf of the ``act`` chain is the agent's wire identity (``agent=prod-agent``):
user -> managed identity -> agent.

This script writes a *dev envelope* (HMAC-signed with a shared secret) so the
example runs offline. In production you do NOT sign here: Entra ID / your IdP
issues a real JWT (via the OBO exchange) and Warden verifies it with
``--jwks-url`` / ``--aud``. Adapters never mint authority themselves -- they only
shape claims; the platform issuer signs. See the README ("Production" section)
and ``../../docs/platform-integration.md``.

Usage:
    python mint_token.py [user_email]
"""

from __future__ import annotations

import sys
from pathlib import Path

from warden_sdk.adapters import azure

AGENT = "prod-agent"
AUDIENCE = "warden:azure"
TOKEN_PATH = ".warden/token.json"
DEV_KEY = "dev-secret"


def main() -> None:
    user = sys.argv[1] if len(sys.argv) > 1 else "alice@contoso.com"

    # A realistic decoded Entra OBO context. In production this is the token the
    # OBO exchange hands the agent -- claims from Entra ID, the agent's managed
    # identity, and Azure RBAC -- not a literal here.
    entra_context = {
        "user": user,                                # Entra oid/upn -> accountable sub
        "managed_identity": "agent-mi",              # agent's managed identity -> middle act
        "app_roles": ["Analyst"],                    # Entra app roles / groups -> roles (RBAC)
        "attributes": {"tenant": "contoso"},         # directory attrs -> attrs (ABAC)
        "scopes": ["Search.Query"],                  # delegated OAuth scopes -> scope
        "role_assignments": [                        # Azure RBAC on a resource -> rel (ReBAC)
            {"role": "Reader", "resource": "storage:reports"},
        ],
    }

    tok = azure.from_entra_obo(entra_context, agent=AGENT, audience=AUDIENCE)

    Path(".warden").mkdir(parents=True, exist_ok=True)
    tok.write_dev_envelope(TOKEN_PATH, key=DEV_KEY)

    print(f"wrote {TOKEN_PATH}  (sub={user}, agent={AGENT}, aud={AUDIENCE})")
    print("verify with:")
    print(
        f"  warden token verify --token {TOKEN_PATH} "
        f"--agent {AGENT} --aud {AUDIENCE} --token-key {DEV_KEY}"
    )


if __name__ == "__main__":
    main()
