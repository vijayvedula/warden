"""Helpers to run an agent's tools *through* the Warden proxy.

The only integration change an agent framework needs is to launch
``warden proxy ...`` instead of its tool server. These helpers build the
argument vector and the MCP client stanza so orchestration shims and examples
stay consistent.
"""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field


def find_warden(explicit: str | None = None) -> str:
    candidate = explicit or os.environ.get("WARDEN_BIN") or shutil.which("warden")
    if not candidate:
        raise FileNotFoundError(
            "warden binary not found; set WARDEN_BIN or put `warden` on PATH"
        )
    return candidate


@dataclass
class ProxyConfig:
    """Describe a ``warden proxy`` invocation in front of one tool server."""

    upstream: str
    agent: str = "agent"
    policy: str = "warden.policy.toml"
    audit: str = ".warden/audit.jsonl"
    approvals: str = ".warden/approvals.json"
    token: str | None = None
    audience: str | None = None
    issuer: str | None = None
    jwks_url: str | None = None
    request_identity: bool = False
    log_format: str = "json"
    extra_args: list[str] = field(default_factory=list)
    warden_bin: str | None = None

    def args(self) -> list[str]:
        """The ``proxy ...`` argument vector (without the binary itself)."""
        a = [
            "proxy",
            "--upstream", self.upstream,
            "--agent", self.agent,
            "--policy", self.policy,
            "--audit", self.audit,
            "--approvals", self.approvals,
            "--log-format", self.log_format,
        ]
        if self.token:
            a += ["--token", self.token]
        if self.audience:
            a += ["--aud", self.audience]
        if self.issuer:
            a += ["--iss", self.issuer]
        if self.jwks_url:
            a += ["--jwks-url", self.jwks_url]
        if self.request_identity:
            a += ["--request-identity"]
        a += self.extra_args
        return a

    def command(self) -> list[str]:
        """Full command including the resolved binary path."""
        return [find_warden(self.warden_bin), *self.args()]

    def mcp_stdio_config(self) -> dict:
        """An MCP stdio server stanza pointing at this proxy.

        Shape consumed by ``langchain_mcp_adapters`` /
        ``MultiServerMCPClient`` and compatible clients.
        """
        cmd = self.command()
        return {
            "command": cmd[0],
            "args": cmd[1:],
            "transport": "stdio",
        }
