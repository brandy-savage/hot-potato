"""
MCP (Model Context Protocol) integration — intercept MCP tool calls before
they reach the host, evaluate against the capability firewall.

Usage:
    from integrations.mcp_guard import MCPGuard

    guard = MCPGuard(firewall=CapabilityFirewall())

    # Wrap your MCP server's tool dispatch:
    @app.call_tool()
    async def call_tool(name: str, arguments: dict) -> Any:
        result = guard.evaluate_mcp_call(
            tool_name=name,
            args=arguments,
            tainted_sources=current_tainted_sources,
        )
        if result.is_blocked:
            return {"error": result.reason}
        return await real_tool_handler(name, arguments)
"""
from __future__ import annotations

import logging
from typing import Any

from hot_potato.core.taint import TaintedArtifact
from hot_potato.core.capabilities import CapabilityFirewall, CapabilityRequest
from hot_potato.core.policy import PolicyDecision

log = logging.getLogger("hot_potato.integrations.mcp")


class MCPGuard:
    """
    Firewall enforcement for MCP tool calls.

    Tainted sources are typically: fetched URLs, uploaded files, RAG results,
    external tool outputs — anything not from the operator's trusted system prompt.
    """

    def __init__(
        self,
        firewall: CapabilityFirewall | None = None,
        *,
        model: str = "mcp-client",
    ) -> None:
        self._firewall = firewall or CapabilityFirewall()
        self._model = model

    def evaluate_mcp_call(
        self,
        tool_name: str,
        args: dict[str, Any],
        *,
        tainted_sources: list[TaintedArtifact] | None = None,
    ) -> PolicyDecision:
        request = CapabilityRequest(
            tool_name=tool_name,
            args=args,
            tainted_inputs=tainted_sources or [],
            requesting_model=self._model,
        )
        return self._firewall.evaluate(request)

    def audit_log(self) -> list[dict]:
        return self._firewall.audit_log()


__all__ = ["MCPGuard"]
