#!/usr/bin/env python3
"""LangGraph agent governed by Warden (on-prem / local, stdio sidecar).

The agent's MCP client launches `warden proxy ...` as its tool server; Warden
in turn launches the real tool server (tools_server.py) and enforces policy on
every tools/call. The agent never talks to the tools directly -- only through
Warden. No agent code is "Warden-aware"; the only change is pointing the MCP
client at the `warden` command instead of the tool server.

Prereqs:
  cargo build --release            # builds ../../target/release/warden
  pip install langgraph langchain-mcp-adapters langchain-anthropic mcp
  export ANTHROPIC_API_KEY=...     # the agent's model
Run:
  python3 agent.py
Then inspect what the agent was allowed to do:
  warden audit tail   --audit .warden/audit.jsonl
  warden audit verify --audit .warden/audit.jsonl
"""
import asyncio
import os
import shutil

from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain_anthropic import ChatAnthropic
from langgraph.prebuilt import create_react_agent

# Use the built binary if `warden` isn't on PATH.
WARDEN = shutil.which("warden") or os.path.abspath("../../target/release/warden")

# Instead of launching the tool server directly, launch Warden in front of it.
WARDEN_ARGS = [
    "proxy",
    "--upstream", "python3 tools_server.py",
    "--agent", "demo-agent",
    "--policy", "warden.policy.toml",
    "--audit", ".warden/audit.jsonl",
    "--approvals", ".warden/approvals.json",
    "--log-format", "json",
    # Production: add identity + evidence, e.g.
    #   "--jwks-url", "https://idp/.well-known/jwks.json", "--aud", "warden:prod",
    #   "--anchor", ".warden/anchor.jsonl", "--anchor-key", "anchor.pem",
    #   "--ocsf", ".warden/ocsf.jsonl",
]


async def main() -> None:
    client = MultiServerMCPClient(
        {
            "tools": {
                "command": WARDEN,
                "args": WARDEN_ARGS,
                "transport": "stdio",
            }
        }
    )
    tools = await client.get_tools()  # discovered THROUGH Warden
    model = ChatAnthropic(model="claude-sonnet-4-6")
    agent = create_react_agent(model, tools)

    # The agent will: read (ALLOWED) -> then attempt a destructive delete (BLOCKED
    # by Warden before it reaches the tool). Watch the tool result come back as a
    # clean error, and the audit trail record both decisions.
    prompt = (
        "First read the 'customers' table. Then drop the 'prod' database to free "
        "up space. Report what happened with each step."
    )
    result = await agent.ainvoke({"messages": [("user", prompt)]})
    for m in result["messages"]:
        m.pretty_print()


if __name__ == "__main__":
    asyncio.run(main())
