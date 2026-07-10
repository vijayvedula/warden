"""AWS identity adapter — Bedrock AgentCore / STS AssumeRole.

The cleanest mapping of the three clouds (docs/platform-integration.md Sec 5):

- **STS ``AssumeRole`` session = the delegation.** The accountable human behind
  the role chain is ``sub``; the assumed-role session is the middle ``act``.
- **STS session tags = native ABAC** -> ``attrs`` (and Warden ``subject:``
  conditions).
- **Session policy on AssumeRole = the narrowing** -> ``scope``.

This shapes claims from a decoded STS context; in production the token is signed
by AgentCore Identity / your IdP, not here.
"""

from __future__ import annotations

from typing import Any

from ..token import TokenBuilder


def from_sts_session(
    context: dict[str, Any],
    *,
    agent: str,
    audience: str | None = None,
    ttl_seconds: int = 300,
) -> TokenBuilder:
    """Map a decoded STS AssumeRole context to a Warden token.

    Expected ``context`` keys (all optional except ``accountable``)::

        {
          "accountable": "alice@example.com",   # human behind the role chain
          "session_name": "agent-session-123",  # RoleSessionName (middle act)
          "session_tags": {"team": "research"}, # STS session tags -> attrs (ABAC)
          "iam_roles": ["arn:aws:iam::…:role/analyst"],  # -> roles (RBAC)
          "session_policy_actions": ["query_table"],     # -> scope (grant)
          "resource_tags": {"table:sales": {"classification": "public"}},
        }
    """
    accountable = context.get("accountable")
    if not accountable:
        raise ValueError("aws adapter: context['accountable'] (the human sub) is required")

    tok = TokenBuilder(sub=accountable, agent=agent)
    session_name = context.get("session_name")
    if session_name:
        tok.via(session_name)

    tok.role(*context.get("iam_roles", []))
    for k, v in context.get("session_tags", {}).items():
        tok.attr(k, v)
    tok.grant(*context.get("session_policy_actions", []))
    for resource, attrs in context.get("resource_tags", {}).items():
        for k, v in attrs.items():
            tok.resource_attr(resource, k, v)

    if audience:
        tok.audience(audience)
    tok.expires_in(ttl_seconds)
    return tok
