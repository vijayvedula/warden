"""Asymmetric JWT signing for production tokens.

Warden verifies JWTs against an issuer's JWKS or PEM public key and accepts
**only asymmetric algorithms** (RS*/PS*/ES*/EdDSA) — an HS256 token signed with
the public key is rejected. This module is the local/dev signer; in production
the private key should live in a KMS/HSM and the platform issuer should sign
(see the no-forged-authority rule).

Requires the ``jwt`` extra:  ``pip install "warden-sdk[jwt]"``.
"""

from __future__ import annotations

from typing import Any

_ASYMMETRIC = {
    "RS256", "RS384", "RS512",
    "PS256", "PS384", "PS512",
    "ES256", "ES384", "ES512",
    "EdDSA",
}


class JwtSigner:
    """Sign Warden claims as a compact JWT with an asymmetric private key.

    ``private_key_pem`` is a PEM-encoded RSA/EC/Ed25519 private key; ``alg`` must
    match the key type (e.g. ``ES256`` for a P-256 EC key). ``default_kid`` is
    written into the JWT header so Warden can select the matching JWKS key.
    """

    def __init__(self, private_key_pem: str | bytes, alg: str, default_kid: str | None = None):
        if alg not in _ASYMMETRIC:
            raise ValueError(
                f"algorithm {alg!r} is not asymmetric; Warden rejects it. "
                f"Use one of: {', '.join(sorted(_ASYMMETRIC))}"
            )
        self._key = private_key_pem
        self._alg = alg
        self._default_kid = default_kid

    def sign(
        self,
        claims: dict[str, Any],
        *,
        kid: str | None = None,
        at_jwt: bool = False,
    ) -> str:
        try:
            import jwt  # PyJWT
        except ImportError as e:  # pragma: no cover - exercised via the extra
            raise ImportError(
                "JWT signing needs the 'jwt' extra: pip install 'warden-sdk[jwt]'"
            ) from e

        headers: dict[str, Any] = {}
        selected_kid = kid or self._default_kid
        if selected_kid:
            headers["kid"] = selected_kid
        if at_jwt:
            # RFC 9068: mark OAuth access tokens so --require-at-jwt accepts them.
            headers["typ"] = "at+jwt"
        return jwt.encode(claims, self._key, algorithm=self._alg, headers=headers)

    @classmethod
    def from_file(cls, path: str, alg: str, default_kid: str | None = None) -> JwtSigner:
        with open(path, "rb") as f:
            return cls(f.read(), alg, default_kid)
