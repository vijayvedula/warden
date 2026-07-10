"""End-to-end conformance: SDK-built tokens must verify under the real binary.

These tests shell out to ``warden token verify`` — the exact check the proxy runs
before forwarding a call. They are skipped automatically if the binary is not
built (see conftest.py).
"""

from warden_sdk import TokenBuilder, verify_token
from warden_sdk.adapters import aws, databricks

KEY = "conformance-dev-secret"
AUD = "warden:test"
AGENT = "prod-agent"


def test_signed_dev_envelope_verifies(warden_bin):
    env = (
        TokenBuilder(sub="alice@example.com", agent=AGENT)
        .via("svc-principal")
        .role("analyst")
        .audience(AUD)
        .expires_in(300)
        .dev_envelope(key=KEY)
    )
    result = verify_token(
        env, agent=AGENT, audience=AUD, token_key=KEY, warden_bin=warden_bin
    )
    assert result.ok, result.output
    assert "token OK" in result.output
    assert "alice@example.com" in result.output


def test_wrong_agent_is_rejected(warden_bin):
    env = TokenBuilder(sub="alice", agent=AGENT).audience(AUD).dev_envelope(key=KEY)
    result = verify_token(
        env, agent="different-agent", audience=AUD, token_key=KEY, warden_bin=warden_bin
    )
    assert not result.ok  # leaf actor != wire identity -> fail closed


def test_tampered_signature_is_rejected(warden_bin):
    env = TokenBuilder(sub="alice", agent=AGENT).audience(AUD).dev_envelope(key=KEY)
    env["claims"]["roles"] = ["admin"]  # mutate after signing
    result = verify_token(
        env, agent=AGENT, audience=AUD, token_key=KEY, warden_bin=warden_bin
    )
    assert not result.ok  # signature no longer covers the claims


def test_aws_adapter_output_is_conformant(warden_bin):
    tok = aws.from_sts_session(
        {
            "accountable": "alice@example.com",
            "session_name": "agent-session",
            "iam_roles": ["analyst"],
            "session_policy_actions": ["query_table"],
        },
        agent=AGENT,
        audience=AUD,
    )
    result = verify_token(
        tok.dev_envelope(key=KEY),
        agent=AGENT,
        audience=AUD,
        token_key=KEY,
        warden_bin=warden_bin,
    )
    assert result.ok, result.output


def test_databricks_adapter_output_is_conformant(warden_bin):
    tok = databricks.from_obo(
        {
            "user": "alice@example.com",
            "service_principal": "sp-agent",
            "uc_grants": [{"privilege": "SELECT", "securable": "table:main.sales"}],
        },
        agent=AGENT,
        audience=AUD,
    )
    result = verify_token(
        tok.dev_envelope(key=KEY),
        agent=AGENT,
        audience=AUD,
        token_key=KEY,
        warden_bin=warden_bin,
    )
    assert result.ok, result.output
