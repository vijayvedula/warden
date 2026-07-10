"""Azure identity adapter — Azure AI Foundry Agent Service / Entra ID.

Microsoft Entra ID mints the credential. An agent runs under a **managed
identity** (or app registration) and acts **on behalf of** a signed-in user via
the OAuth 2.0 OBO flow: the user is the accountable ``sub``, the managed identity
is the middle ``act``, the agent is the leaf. Entra **app roles** / group claims
map to ``roles``; directory/resource attributes map to ``attrs``; Azure RBAC
role assignments scoped to a resource map to ``rel``.
"""

from __future__ import annotations

from typing import Any

from ..token import TokenBuilder


def from_entra_obo(
    context: dict[str, Any],
    *,
    agent: str,
    audience: str | None = None,
    ttl_seconds: int = 300,
) -> TokenBuilder:
    """Map an Entra ID on-behalf-of context to a Warden token.

    Expected ``context`` keys::

        {
          "user": "alice@contoso.com",            # oid/upn -> accountable sub
          "managed_identity": "agent-mi",         # middle act
          "app_roles": ["Analyst"],               # Entra app roles / groups -> roles
          "attributes": {"tenant": "contoso"},    # directory attrs -> attrs (ABAC)
          "scopes": ["Search.Query"],             # delegated scopes -> scope
          "role_assignments": [                   # Azure RBAC on a resource -> rel
            {"role": "Reader", "resource": "storage:reports"},
          ],
        }
    """
    user = context.get("user")
    if not user:
        raise ValueError("azure adapter: context['user'] (the human sub) is required")

    tok = TokenBuilder(sub=user, agent=agent)
    mi = context.get("managed_identity")
    if mi:
        tok.via(mi)

    tok.role(*context.get("app_roles", []))
    for k, v in context.get("attributes", {}).items():
        tok.attr(k, v)
    tok.grant(*context.get("scopes", []))
    for ra in context.get("role_assignments", []):
        tok.relation(ra["role"].lower(), ra["resource"])

    if audience:
        tok.audience(audience)
    tok.expires_in(ttl_seconds)
    return tok
