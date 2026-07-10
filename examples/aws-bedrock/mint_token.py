#!/usr/bin/env python3
"""Mint a Warden identity token from an AWS STS AssumeRole context.

In production these values are NOT hand-written -- they come from the STS
``AssumeRole`` call that AgentCore Identity (or your IdP) performs to give the
agent its session:

    - ``accountable``            the human behind the role chain           -> ``sub``
    - ``session_name``           STS ``RoleSessionName``                   -> middle ``act`` hop
    - ``session_tags``           STS session tags (native ABAC)            -> ``attrs``
    - ``iam_roles``              the assumed IAM role(s)                    -> ``roles`` (RBAC)
    - ``session_policy_actions`` the AssumeRole session-policy narrowing   -> ``scope`` (grant)
    - ``resource_tags``          tags on the resources the tools touch     -> ``resource_attrs``

The leaf of the ``act`` chain is the agent's wire identity (``agent=prod-agent``).

This script writes a *dev envelope* (HMAC-signed with a shared secret) so the
example runs offline. In production you do NOT sign here: AgentCore Identity /
your IdP issues a real JWT and Warden verifies it with ``--jwks-url`` / ``--aud``.
See the README ("Production" section) and ``../../docs/platform-integration.md`` (Sec 5).

Usage:
    python mint_token.py [accountable_email]
"""

from __future__ import annotations

import sys
from pathlib import Path

from warden_sdk.adapters import aws

AGENT = "prod-agent"
AUDIENCE = "warden:aws"
TOKEN_PATH = ".warden/token.json"
DEV_KEY = "dev-secret"


def main() -> None:
    accountable = sys.argv[1] if len(sys.argv) > 1 else "alice@example.com"

    # A realistic decoded STS AssumeRole context. In production this is the
    # session AgentCore Identity hands the agent -- not a literal here.
    sts_context = {
        "accountable": accountable,
        "session_name": "agent-session-123",
        "session_tags": {"team": "research"},
        "iam_roles": ["arn:aws:iam::111122223333:role/analyst"],
        "session_policy_actions": ["query_table"],
        "resource_tags": {"table:sales": {"classification": "public"}},
    }

    tok = aws.from_sts_session(sts_context, agent=AGENT, audience=AUDIENCE)

    Path(".warden").mkdir(parents=True, exist_ok=True)
    tok.write_dev_envelope(TOKEN_PATH, key=DEV_KEY)

    print(f"wrote {TOKEN_PATH}  (sub={accountable}, agent={AGENT}, aud={AUDIENCE})")
    print("verify with:")
    print(
        f"  warden token verify --token {TOKEN_PATH} "
        f"--agent {AGENT} --aud {AUDIENCE} --token-key {DEV_KEY}"
    )


if __name__ == "__main__":
    main()
