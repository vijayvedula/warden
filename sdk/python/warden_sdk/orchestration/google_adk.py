"""Google ADK orchestration shim.

The Agent Development Kit consumes tools via an MCP toolset. This shim builds the
stdio connection parameters that launch ``warden proxy`` as that toolset's
server, so an ADK agent's tool calls are governed by Warden. It composes with the
Google identity adapter, which mints the token (workload identity / service
account).
"""

from __future__ import annotations

from ..proxy import ProxyConfig


def warden_connection_params(proxy: ProxyConfig) -> dict:
    """Stdio connection parameters (command + args) for an ADK MCP toolset.

    Usage (ADK)::

        from google.adk.tools.mcp_tool.mcp_toolset import (
            MCPToolset, StdioServerParameters,
        )
        from warden_sdk import ProxyConfig
        from warden_sdk.orchestration import google_adk as wg

        cfg = ProxyConfig(upstream="python3 tools_server.py", agent="prod-agent",
                          token=".warden/token.json")
        params = wg.warden_connection_params(cfg)
        toolset = MCPToolset(
            connection_params=StdioServerParameters(**params)
        )
    """
    cmd = proxy.command()
    return {"command": cmd[0], "args": cmd[1:]}
