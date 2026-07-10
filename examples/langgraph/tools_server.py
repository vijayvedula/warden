#!/usr/bin/env python3
"""A tiny MCP tool server for the LangGraph + Warden example.

Exposes three tools so policy can demonstrate allow / hold / deny:
  - read_records   (safe -> allow)
  - create_ticket  (outbound -> require_approval)
  - delete_database(destructive -> deny)

Warden launches THIS as its `--upstream` and governs every tools/call.
Run standalone for a sanity check: `python3 tools_server.py` (speaks MCP stdio).

Requires: pip install mcp
"""
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo-tools")


@mcp.tool()
def read_records(table: str) -> str:
    """Read rows from a table (read-only)."""
    return f"read 3 records from {table}"


@mcp.tool()
def create_ticket(title: str, body: str = "") -> str:
    """Create a ticket (outbound side effect)."""
    return f"created ticket: {title}"


@mcp.tool()
def delete_database(name: str) -> str:
    """Drop a database (destructive)."""
    return f"DROPPED database {name}"


if __name__ == "__main__":
    mcp.run()  # stdio transport
