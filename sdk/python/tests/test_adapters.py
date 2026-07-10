import pytest

from warden_sdk.adapters import aws, azure, databricks, google


def test_aws_sts_mapping():
    tok = aws.from_sts_session(
        {
            "accountable": "alice@example.com",
            "session_name": "agent-session",
            "session_tags": {"team": "research"},
            "iam_roles": ["arn:aws:iam::1:role/analyst"],
            "session_policy_actions": ["query_table"],
            "resource_tags": {"table:sales": {"classification": "public"}},
        },
        agent="prod-agent",
        audience="warden:prod",
    )
    c = tok.claims()
    assert c["sub"] == "alice@example.com"
    assert c["act"] == {"sub": "agent-session", "act": {"sub": "prod-agent"}}
    assert c["attrs"] == {"team": "research"}
    assert c["roles"] == ["arn:aws:iam::1:role/analyst"]
    assert c["scope"] == ["query_table"]
    assert c["resource_attrs"] == {"table:sales": {"classification": "public"}}
    assert c["aud"] == "warden:prod"


def test_databricks_obo_maps_uc_grants_to_relations():
    tok = databricks.from_obo(
        {
            "user": "alice@example.com",
            "service_principal": "sp-agent",
            "uc_groups": ["analysts"],
            "catalog": "main",
            "uc_grants": [{"privilege": "SELECT", "securable": "table:main.sales"}],
            "tools": ["read_table"],
        },
        agent="prod-agent",
    )
    c = tok.claims()
    assert c["act"] == {"sub": "sp-agent", "act": {"sub": "prod-agent"}}
    assert c["roles"] == ["analysts"]
    assert c["attrs"] == {"catalog": "main"}
    assert c["rel"] == [{"relation": "select", "resource": "table:main.sales"}]
    assert c["scope"] == ["read_table"]


def test_google_workload_identity_mapping():
    tok = google.from_workload_identity(
        {
            "user": "alice@example.com",
            "service_account": "agent@proj.iam.gserviceaccount.com",
            "iam_roles": ["roles/bigquery.dataViewer"],
            "iam_conditions": {"resource.type": "bigquery"},
            "a2a_capabilities": ["query_dataset"],
            "resource_bindings": [{"relation": "dataViewer", "resource": "dataset:analytics"}],
        },
        agent="prod-agent",
    )
    c = tok.claims()
    assert c["act"]["sub"] == "agent@proj.iam.gserviceaccount.com"
    assert c["attrs"] == {"resource.type": "bigquery"}
    assert c["rel"] == [{"relation": "dataViewer", "resource": "dataset:analytics"}]
    assert c["scope"] == ["query_dataset"]


def test_azure_entra_obo_mapping():
    tok = azure.from_entra_obo(
        {
            "user": "alice@contoso.com",
            "managed_identity": "agent-mi",
            "app_roles": ["Analyst"],
            "attributes": {"tenant": "contoso"},
            "scopes": ["Search.Query"],
            "role_assignments": [{"role": "Reader", "resource": "storage:reports"}],
        },
        agent="prod-agent",
    )
    c = tok.claims()
    assert c["act"] == {"sub": "agent-mi", "act": {"sub": "prod-agent"}}
    assert c["roles"] == ["Analyst"]
    assert c["rel"] == [{"relation": "reader", "resource": "storage:reports"}]
    assert c["scope"] == ["Search.Query"]


@pytest.mark.parametrize(
    "fn,ctx",
    [
        (aws.from_sts_session, {}),
        (databricks.from_obo, {}),
        (google.from_workload_identity, {}),
        (azure.from_entra_obo, {}),
    ],
)
def test_adapters_require_accountable_human(fn, ctx):
    with pytest.raises(ValueError):
        fn(ctx, agent="agent")
