"""Databricks identity adapter — Mosaic AI Agent Framework / Unity Catalog.

The agent runs as a **service principal** with **on-behalf-of-user** auth: the
human who triggered the agent is the accountable ``sub``, the service principal
is the middle ``act``, the agent is the leaf (docs/platform-integration.md
Sec 3). Unity Catalog governs the data layer — map UC grants on a securable to
``rel`` tuples so "the agent may call this UC function only on tables the user
can read" is enforced at the action boundary and is replay-proof.
"""

from __future__ import annotations

from typing import Any

from ..token import TokenBuilder


def from_obo(
    context: dict[str, Any],
    *,
    agent: str,
    audience: str | None = None,
    ttl_seconds: int = 300,
) -> TokenBuilder:
    """Map a Databricks on-behalf-of-user context to a Warden token.

    Expected ``context`` keys::

        {
          "user": "alice@example.com",           # OBO user -> accountable sub
          "service_principal": "sp-agent-runtime",  # middle act
          "uc_groups": ["analysts"],             # UC group membership -> roles
          "workspace": "ws-123",                 # workspace/catalog context -> attrs
          "catalog": "main",
          "uc_grants": [                         # UC grants on securables -> rel
            {"privilege": "SELECT", "securable": "table:main.sales"},
          ],
          "tools": ["read_table"],               # registered UC functions -> scope
        }
    """
    user = context.get("user")
    if not user:
        raise ValueError("databricks adapter: context['user'] (the human sub) is required")

    tok = TokenBuilder(sub=user, agent=agent)
    sp = context.get("service_principal")
    if sp:
        tok.via(sp)

    tok.role(*context.get("uc_groups", []))
    if context.get("workspace"):
        tok.attr("workspace", context["workspace"])
    if context.get("catalog"):
        tok.attr("catalog", context["catalog"])
    for grant in context.get("uc_grants", []):
        # UC privilege on a securable -> ReBAC relation tuple.
        tok.relation(grant["privilege"].lower(), grant["securable"])
    tok.grant(*context.get("tools", []))

    if audience:
        tok.audience(audience)
    tok.expires_in(ttl_seconds)
    return tok
