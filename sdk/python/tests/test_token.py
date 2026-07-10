import pytest

from warden_sdk import TokenBuilder
from warden_sdk.canonical import dev_signature


def test_leaf_actor_is_the_agent():
    c = TokenBuilder(sub="alice", agent="prod-agent").claims()
    assert c["sub"] == "alice"
    assert c["act"] == {"sub": "prod-agent"}


def test_via_builds_nested_act_chain_leaf_last():
    c = TokenBuilder(sub="alice", agent="agent").via("svc").claims()
    # human(sub=alice) -> svc(act.sub) -> agent(act.act.sub)
    assert c["act"] == {"sub": "svc", "act": {"sub": "agent"}}


def test_multiple_intermediates_order_preserved():
    c = TokenBuilder(sub="alice", agent="leaf").via("a", "b").claims()
    assert c["act"] == {"sub": "a", "act": {"sub": "b", "act": {"sub": "leaf"}}}


def test_authorization_claims():
    c = (
        TokenBuilder(sub="alice", agent="agent")
        .role("analyst", "reader")
        .attr("team", "research")
        .relation("can_read", "table:sales")
        .grant("query_table")
        .resource_attr("table:sales", "classification", "public")
        .claims()
    )
    assert c["roles"] == ["analyst", "reader"]
    assert c["attrs"] == {"team": "research"}
    assert c["rel"] == [{"relation": "can_read", "resource": "table:sales"}]
    assert c["scope"] == ["query_table"]
    assert c["resource_attrs"] == {"table:sales": {"classification": "public"}}


def test_empty_optionals_are_omitted():
    c = TokenBuilder(sub="alice", agent="agent").claims()
    for k in ("roles", "attrs", "rel", "scope", "resource_attrs", "aud"):
        assert k not in c


def test_requires_sub_and_agent():
    with pytest.raises(ValueError):
        TokenBuilder(sub="", agent="agent")
    with pytest.raises(ValueError):
        TokenBuilder(sub="alice", agent="")


def test_dev_envelope_signature_present_when_keyed():
    b = TokenBuilder(sub="alice", agent="agent").audience("warden:prod")
    env = b.dev_envelope(key="dev-secret")
    assert env["claims"]["sub"] == "alice"
    assert env["sig"] == dev_signature(env["claims"], "dev-secret")


def test_dev_envelope_unsigned_when_no_key():
    env = TokenBuilder(sub="alice", agent="agent").dev_envelope()
    assert "sig" not in env


def test_dpop_binding():
    c = TokenBuilder(sub="alice", agent="agent").dpop_jkt("thumb123").claims()
    assert c["cnf"] == {"jkt": "thumb123"}
