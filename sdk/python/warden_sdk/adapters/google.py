"""Google identity adapter — Vertex AI Agent Engine / ADK / A2A.

Google IAM mints the credential: the agent uses a **service account** (or
workload identity); the accountable human is carried via the OIDC ``sub`` /
domain-wide-delegation subject. IAM **conditions** map cleanly to ``attrs``
(ABAC). For inter-agent (A2A) calls, an agent card's declared capabilities map
to ``scope`` and each hop extends the ``act`` chain
(docs/platform-integration.md Sec 4).
"""

from __future__ import annotations

from typing import Any

from ..token import TokenBuilder


def from_workload_identity(
    context: dict[str, Any],
    *,
    agent: str,
    audience: str | None = None,
    ttl_seconds: int = 300,
) -> TokenBuilder:
    """Map a Google workload-identity / service-account context to a Warden token.

    Expected ``context`` keys::

        {
          "user": "alice@example.com",        # OIDC sub / DWD subject -> accountable
          "service_account": "agent@proj.iam.gserviceaccount.com",  # middle act
          "iam_roles": ["roles/bigquery.dataViewer"],  # -> roles
          "iam_conditions": {"resource.type": "bigquery"},  # IAM conditions -> attrs
          "a2a_capabilities": ["query_dataset"],  # agent-card capabilities -> scope
          "resource_bindings": [               # resource-level IAM -> rel
            {"relation": "dataViewer", "resource": "dataset:analytics"},
          ],
        }
    """
    user = context.get("user")
    if not user:
        raise ValueError("google adapter: context['user'] (the human sub) is required")

    tok = TokenBuilder(sub=user, agent=agent)
    sa = context.get("service_account")
    if sa:
        tok.via(sa)

    tok.role(*context.get("iam_roles", []))
    for k, v in context.get("iam_conditions", {}).items():
        tok.attr(k, v)
    tok.grant(*context.get("a2a_capabilities", []))
    for binding in context.get("resource_bindings", []):
        tok.relation(binding["relation"], binding["resource"])

    if audience:
        tok.audience(audience)
    tok.expires_in(ttl_seconds)
    return tok
