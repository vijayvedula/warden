"""LangGraph orchestration shim.

A LangGraph app has no identity issuer of its own — it composes with an identity
adapter (docs/platform-integration.md Sec 8). This shim's only job is to point
the agent's MCP client at ``warden proxy`` instead of the tool server, so every
tool call is governed without the agent code being Warden-aware.
"""

from __future__ import annotations

from ..proxy import ProxyConfig


def warden_mcp_servers(
    proxy: ProxyConfig,
    *,
    server_name: str = "tools",
) -> dict:
    """Build the ``MultiServerMCPClient`` config that routes through Warden.

    Usage::

        from langchain_mcp_adapters.client import MultiServerMCPClient
        from warden_sdk.orchestration import langgraph as wl
        from warden_sdk import ProxyConfig

        cfg = ProxyConfig(upstream="python3 tools_server.py", agent="prod-agent",
                          token=".warden/token.json")
        client = MultiServerMCPClient(wl.warden_mcp_servers(cfg))
        tools = await client.get_tools()   # discovered THROUGH Warden
    """
    return {server_name: proxy.mcp_stdio_config()}


def warden_stdio_client(proxy: ProxyConfig, *, server_name: str = "tools"):
    """Convenience: construct a ``MultiServerMCPClient`` if the deps are present."""
    try:
        from langchain_mcp_adapters.client import MultiServerMCPClient
    except ImportError as e:  # pragma: no cover
        raise ImportError(
            "langchain-mcp-adapters is required: pip install langchain-mcp-adapters"
        ) from e
    return MultiServerMCPClient(warden_mcp_servers(proxy, server_name=server_name))
