"""Production JWT path: an ES256-signed token verifies against the issuer PEM.

Uses the repo's EC test fixtures. Requires PyJWT (the ``dev``/``jwt`` extra) and
the built binary; skipped otherwise.
"""

import os

import pytest

from warden_sdk import JwtSigner, TokenBuilder
from warden_sdk.conformance import verify_jwt

pytest.importorskip("jwt")

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
EC_PRIV = os.path.join(REPO_ROOT, "fixtures", "test_ec_priv.pem")
EC_PUB = os.path.join(REPO_ROOT, "fixtures", "test_ec_pub.pem")

AUD = "warden:test"
AGENT = "prod-agent"


@pytest.mark.skipif(not os.path.exists(EC_PRIV), reason="EC fixtures not present")
def test_es256_jwt_verifies_against_issuer_pem(warden_bin):
    signer = JwtSigner.from_file(EC_PRIV, alg="ES256", default_kid="k1")
    jwt = (
        TokenBuilder(sub="alice@example.com", agent=AGENT)
        .via("svc")
        .role("analyst")
        .audience(AUD)
        .expires_in(300)
        .to_jwt(signer, at_jwt=True)
    )
    result = verify_jwt(
        jwt,
        agent=AGENT,
        issuer_key_pem_path=EC_PUB,
        audience=AUD,
        at_jwt=True,
        warden_bin=warden_bin,
    )
    assert result.ok, result.output
    assert "token OK" in result.output


def test_signer_rejects_symmetric_alg():
    with pytest.raises(ValueError):
        JwtSigner(b"secret", alg="HS256")
