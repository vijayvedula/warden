#!/usr/bin/env python3
"""Mint a Warden delegation token for the LangGraph example.

By default the example runs without identity (policy `require_identity` off). To
turn on accountability — every action tied to a named human — mint a token here
and launch Warden with it.

A LangGraph app has no identity issuer of its own, so in production you compose
this with a cloud identity adapter (see ../databricks, ../aws-bedrock, etc.).
For a local walkthrough we emit a dev-envelope token verified with --token-key.

Usage:
  python3 mint_token.py [user_email]

Then run the agent with identity enforced:
  warden proxy --upstream "python3 tools_server.py" --agent demo-agent \
    --policy warden.policy.toml --token .warden/token.json \
    --aud warden:langgraph --token-key dev-secret
  # (set require_identity = true in warden.policy.toml to fail closed)
"""
import os
import sys

from warden_sdk import ProxyConfig, TokenBuilder

AGENT = "demo-agent"
AUD = "warden:langgraph"
KEY = "dev-secret"  # dev only; production signs a real JWT via your IdP/KMS


def main() -> None:
    user = sys.argv[1] if len(sys.argv) > 1 else "alice@example.com"
    os.makedirs(".warden", exist_ok=True)

    tok = (
        TokenBuilder(sub=user, agent=AGENT)
        .role("data.reader")
        .grant("read_records", "create_ticket")
        .audience(AUD)
        .expires_in(3600)
    )
    path = tok.write_dev_envelope(".warden/token.json", key=KEY)
    print(f"wrote {path}  (accountable: {user}, agent: {AGENT})")

    # The exact proxy command the agent would launch, with identity attached.
    cfg = ProxyConfig(
        upstream="python3 tools_server.py",
        agent=AGENT,
        policy="warden.policy.toml",
        token=path,
        audience=AUD,
        extra_args=["--token-key", KEY],
    )
    print("\nverify the token:")
    print(
        f"  warden token verify --token {path} --agent {AGENT} "
        f"--aud {AUD} --token-key {KEY}"
    )
    print("\nrun the proxy with identity enforced:")
    print("  " + " ".join(cfg.command()))


if __name__ == "__main__":
    main()
