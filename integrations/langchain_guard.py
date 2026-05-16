"""
LangChain integration — wraps LangChain tools with capability firewall.

Usage:
    from integrations.langchain_guard import GuardedTool
    from langchain_core.tools import tool

    @tool
    def send_http(url: str, data: str) -> str:
        return requests.post(url, data=data).text

    guarded = GuardedTool.wrap(send_http, firewall=CapabilityFirewall())

    # Use guarded instead of send_http in your agent
    agent = create_tool_calling_agent(llm, [guarded], prompt)
"""
from __future__ import annotations

import logging
from typing import Any

from hot_potato.core.taint import TaintedArtifact
from hot_potato.core.capabilities import CapabilityFirewall, CapabilityRequest, CapabilityDenied

log = logging.getLogger("hot_potato.integrations.langchain")

# Thread-local storage for taint context
import threading
_taint_ctx = threading.local()


def set_taint_context(artifacts: list[TaintedArtifact]) -> None:
    """Set tainted artifacts for the current execution context."""
    _taint_ctx.artifacts = artifacts


def clear_taint_context() -> None:
    _taint_ctx.artifacts = []


def get_taint_context() -> list[TaintedArtifact]:
    return getattr(_taint_ctx, "artifacts", [])


class GuardedTool:
    """
    Wraps a LangChain-compatible tool with capability firewall enforcement.
    Reads taint context from thread-local storage set by set_taint_context().
    """

    def __init__(self, tool: Any, firewall: CapabilityFirewall) -> None:
        self._tool = tool
        self._firewall = firewall
        # Proxy tool metadata
        self.name = getattr(tool, "name", str(tool))
        self.description = getattr(tool, "description", "")
        self.args_schema = getattr(tool, "args_schema", None)

    @classmethod
    def wrap(cls, tool: Any, firewall: CapabilityFirewall | None = None) -> "GuardedTool":
        return cls(tool, firewall or CapabilityFirewall())

    def invoke(self, input: Any, **kwargs: Any) -> Any:
        tainted = get_taint_context()
        args = input if isinstance(input, dict) else {"input": input}

        request = CapabilityRequest(
            tool_name=self.name,
            args=args,
            tainted_inputs=tainted,
            requesting_model="langchain-agent",
        )

        def executor(req: CapabilityRequest) -> Any:
            return self._tool.invoke(req.args, **kwargs)

        result = self._firewall.mediate(request, executor=executor)

        if not result.allowed:
            raise CapabilityDenied(result.decision)

        return result.result

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        return self.invoke(*args, **kwargs)


__all__ = ["GuardedTool", "set_taint_context", "clear_taint_context", "get_taint_context"]
