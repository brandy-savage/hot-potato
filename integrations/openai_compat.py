"""
OpenAI-compatible integration — wraps the OpenAI tool-use loop with the
hot-potato capability firewall.

Usage:
    from integrations.openai_compat import GuardedToolExecutor
    from openai import OpenAI

    client = OpenAI()
    executor = GuardedToolExecutor(tools=my_tools, firewall=CapabilityFirewall())

    # In your response loop:
    for tool_call in response.choices[0].message.tool_calls:
        result = executor.execute(tool_call, tainted_inputs=[artifact])
        # result.allowed → False means firewall blocked it
"""
from __future__ import annotations

import json
import logging
from typing import Any, Callable

from hot_potato.core.taint import TaintedArtifact
from hot_potato.core.capabilities import (
    CapabilityFirewall, CapabilityRequest, CapabilityResult, CapabilityDenied
)

log = logging.getLogger("hot_potato.integrations.openai")


class GuardedToolExecutor:
    """
    Wraps an OpenAI tool-call loop with capability firewall enforcement.
    All tool calls are evaluated against the policy before execution.
    """

    def __init__(
        self,
        tools: dict[str, Callable],
        firewall: CapabilityFirewall | None = None,
        *,
        model: str = "unknown",
        raise_on_deny: bool = False,
    ) -> None:
        self._tools = tools
        self._firewall = firewall or CapabilityFirewall()
        self._model = model
        self._raise_on_deny = raise_on_deny

    def execute(
        self,
        tool_call: Any,   # openai.types.chat.ChatCompletionMessageToolCall
        *,
        tainted_inputs: list[TaintedArtifact] | None = None,
    ) -> CapabilityResult:
        """
        Evaluate and optionally execute an OpenAI tool call.

        tool_call: the tool_call object from the OpenAI response
        tainted_inputs: TaintedArtifacts that influenced this call
        """
        tool_name = tool_call.function.name
        try:
            args = json.loads(tool_call.function.arguments or "{}")
        except json.JSONDecodeError:
            args = {}

        request = CapabilityRequest(
            tool_name=tool_name,
            args=args,
            tainted_inputs=tainted_inputs or [],
            requesting_model=self._model,
        )

        if tool_name not in self._tools:
            log.warning("Unknown tool: %s", tool_name)
            from hot_potato.core.policy import PolicyDecision, PolicyOutcome
            return CapabilityResult(
                decision=PolicyDecision(
                    outcome=PolicyOutcome.DENY,
                    rule_id="__unknown_tool__",
                    reason=f"Tool '{tool_name}' not registered",
                ),
                executed=False,
            )

        def executor(req: CapabilityRequest) -> Any:
            return self._tools[req.tool_name](**req.args)

        result = self._firewall.mediate(request, executor=executor)

        if not result.allowed and self._raise_on_deny:
            raise CapabilityDenied(result.decision)

        return result

    def format_tool_result(self, tool_call: Any, result: CapabilityResult) -> dict:
        """Format a CapabilityResult as an OpenAI tool message."""
        if result.allowed and result.result is not None:
            content = json.dumps(result.result) if not isinstance(result.result, str) else result.result
        else:
            content = json.dumps({
                "error": "capability_denied",
                "outcome": result.decision.outcome.value,
                "reason": result.decision.reason,
            })
        return {
            "role": "tool",
            "tool_call_id": tool_call.id,
            "content": content,
        }


__all__ = ["GuardedToolExecutor"]
