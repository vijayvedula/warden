"""TokenBuilder — assemble Warden's canonical delegation claims and emit a token.

Warden's identity boundary is a single signed token carrying *who an agent acts
for* (RFC 8693 delegation): ``sub`` is the accountable human, ``act`` is the
nested acting chain whose leaf is the agent on the wire. Everything else —
``roles`` (RBAC), ``attrs`` (ABAC), ``rel`` (ReBAC), ``scope`` (agent grant) —
is trusted-because-signed and consumed by the policy engine.

The builder is deliberately dumb: it *shapes and signs* claims. It never invents
authority. In production the signer should be the platform's issuer/KMS (see the
no-forged-authority rule in docs/platform-integration.md); the local signers
here are for dev, tests, and the conformance kit.
"""

from __future__ import annotations

import json
import time
from typing import Any

from .canonical import dev_signature


def _nested_act(chain: list[str]) -> dict[str, Any] | None:
    """Build the RFC 8693 ``act`` object from an ordered acting chain.

    ``chain`` is outermost-first and ends with the leaf agent, e.g.
    ``["svc-principal", "agent"]`` -> ``{"sub": "svc-principal",
    "act": {"sub": "agent"}}``. Warden's ``leaf_actor`` (deepest ``sub``) must
    equal the ``--agent`` the proxy runs as.
    """
    act: dict[str, Any] | None = None
    for sub in reversed(chain):
        node: dict[str, Any] = {"sub": sub}
        if act is not None:
            node["act"] = act
        act = node
    return act


class TokenBuilder:
    """Fluent builder for a Warden token.

    Example::

        tok = (
            TokenBuilder(sub="alice@example.com", agent="prod-agent")
            .via("svc-principal")
            .role("analyst")
            .relation("can_read", "table:sales")
            .grant("query_table")
            .audience("warden:prod")
            .expires_in(300)
        )
        tok.write_dev_envelope("token.json", key="dev-secret")
    """

    def __init__(self, sub: str, agent: str):
        if not sub or not sub.strip():
            raise ValueError("sub (the accountable human) is required")
        if not agent or not agent.strip():
            raise ValueError("agent (the leaf actor / wire identity) is required")
        self._sub = sub
        self._agent = agent
        self._intermediates: list[str] = []
        self._roles: list[str] = []
        self._attrs: dict[str, Any] = {}
        self._rel: list[dict[str, str]] = []
        self._scope: list[str] = []
        self._resource_attrs: dict[str, dict[str, Any]] = {}
        self._aud: str | None = None
        self._iss: str | None = None
        self._exp: int | None = None
        self._nbf: int | None = None
        self._iat: int | None = None
        self._jti: str | None = None
        self._jkt: str | None = None

    # --- delegation chain -------------------------------------------------
    def via(self, *intermediates: str) -> TokenBuilder:
        """Insert intermediate acting parties between the human and the agent
        (e.g. a service principal or assumed role)."""
        self._intermediates.extend(i for i in intermediates if i)
        return self

    # --- authorization claims --------------------------------------------
    def role(self, *roles: str) -> TokenBuilder:
        self._roles.extend(r for r in roles if r)
        return self

    def attr(self, key: str, value: Any) -> TokenBuilder:
        self._attrs[key] = value
        return self

    def relation(self, relation: str, resource: str) -> TokenBuilder:
        self._rel.append({"relation": relation, "resource": resource})
        return self

    def grant(self, *scopes: str) -> TokenBuilder:
        self._scope.extend(s for s in scopes if s)
        return self

    def resource_attr(self, resource: str, key: str, value: Any) -> TokenBuilder:
        self._resource_attrs.setdefault(resource, {})[key] = value
        return self

    # --- envelope / validity ---------------------------------------------
    def audience(self, aud: str) -> TokenBuilder:
        self._aud = aud
        return self

    def issuer(self, iss: str) -> TokenBuilder:
        self._iss = iss
        return self

    def jti(self, jti: str) -> TokenBuilder:
        self._jti = jti
        return self

    def not_before(self, nbf: int) -> TokenBuilder:
        self._nbf = int(nbf)
        return self

    def expires_in(self, seconds: int, *, now: int | None = None) -> TokenBuilder:
        base = int(now if now is not None else time.time())
        self._iat = base
        self._exp = base + int(seconds)
        return self

    def expires_at(self, epoch: int) -> TokenBuilder:
        self._exp = int(epoch)
        return self

    def dpop_jkt(self, jkt: str) -> TokenBuilder:
        """Bind the token to a DPoP proof key (RFC 7800 ``cnf.jkt``)."""
        self._jkt = jkt
        return self

    # --- output -----------------------------------------------------------
    def claims(self) -> dict[str, Any]:
        """The canonical claims dict (omitting empty optional fields)."""
        c: dict[str, Any] = {"sub": self._sub}
        act = _nested_act(self._intermediates + [self._agent])
        if act is not None:
            c["act"] = act
        if self._roles:
            c["roles"] = self._roles
        if self._attrs:
            c["attrs"] = self._attrs
        if self._rel:
            c["rel"] = self._rel
        if self._scope:
            c["scope"] = self._scope
        if self._resource_attrs:
            c["resource_attrs"] = self._resource_attrs
        if self._aud is not None:
            c["aud"] = self._aud
        if self._iss is not None:
            c["iss"] = self._iss
        if self._exp is not None:
            c["exp"] = self._exp
        if self._nbf is not None:
            c["nbf"] = self._nbf
        if self._iat is not None:
            c["iat"] = self._iat
        if self._jti is not None:
            c["jti"] = self._jti
        if self._jkt is not None:
            c["cnf"] = {"jkt": self._jkt}
        return c

    @property
    def agent(self) -> str:
        return self._agent

    def dev_envelope(self, key: str | None = None) -> dict[str, Any]:
        """A dev-envelope token: ``{"claims": {...}, "sig": ...}``.

        With ``key`` the signature verifies under ``--token-key``; without, it is
        an unsigned dev token. Development/tests only — not an enforcement mode.
        """
        claims = self.claims()
        envelope: dict[str, Any] = {"claims": claims}
        if key is not None:
            envelope["sig"] = dev_signature(claims, key)
        return envelope

    def write_dev_envelope(self, path: str, key: str | None = None) -> str:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.dev_envelope(key), f)
        return path

    def to_jwt(self, signer: object, *, kid: str | None = None, at_jwt: bool = False) -> str:
        """Sign the claims as a compact JWT using an asymmetric ``signer``.

        ``signer`` is a :class:`warden_sdk.signing.JwtSigner` (or anything with a
        matching ``sign(claims, kid, at_jwt)`` method). Warden accepts only
        asymmetric algorithms, blocking the RS256->HS256 confusion downgrade.
        """
        return signer.sign(self.claims(), kid=kid, at_jwt=at_jwt)  # type: ignore[attr-defined]
