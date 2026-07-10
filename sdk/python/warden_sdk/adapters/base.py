"""Identity-adapter contract.

An identity adapter maps a platform's native identity material into a
:class:`~warden_sdk.token.TokenBuilder` carrying Warden's canonical claims. It is
**pure data mapping** — it shapes claims and (in production) asks the platform
issuer to sign; it never mints authority itself (docs/platform-integration.md,
the no-forged-authority rule).

Adapters accept plain dicts (the decoded native credential/context) rather than
live cloud SDK objects, so they are testable offline and free of heavy deps.
"""

from __future__ import annotations

from typing import Any, Protocol

from ..token import TokenBuilder


class IdentityAdapter(Protocol):
    """Turn native identity context into a Warden ``TokenBuilder``."""

    def to_token(self, context: dict[str, Any], *, agent: str) -> TokenBuilder: ...
