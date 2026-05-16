"""
Policy engine — declarative YAML-based rules governing capability requests.

Policy files live in /policies/. The engine loads them, builds a rule chain,
and evaluates each CapabilityRequest in order. First matching rule wins.

Rule structure (YAML):
  rules:
    - id: block_exfil
      description: Block exfiltration tools from untrusted content
      match:
        tools: ["send_http", "send_email", "send_crypto"]
        trust_levels: [UNTRUSTED, SEMI_TRUSTED]
      outcome: deny
      reason: "Exfiltration vector from untrusted content"
"""
from __future__ import annotations

import fnmatch
import logging
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

try:
    import yaml
    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False

from hot_potato.core.taint import TrustLevel

log = logging.getLogger("hot_potato.policy")

POLICIES_DIR = Path(__file__).resolve().parent.parent.parent.parent / "policies"


class PolicyOutcome(str, Enum):
    ALLOW                = "allow"
    DENY                 = "deny"
    REDACT               = "redact"
    REQUIRE_HUMAN_REVIEW = "require_human_review"
    SANDBOX_ONLY         = "sandbox_only"
    SHADOW_EXECUTE       = "shadow_execute"


@dataclass
class PolicyDecision:
    outcome: PolicyOutcome
    rule_id: str
    reason: str
    dry_run: bool = False

    @property
    def is_blocked(self) -> bool:
        return self.outcome in (PolicyOutcome.DENY, PolicyOutcome.REQUIRE_HUMAN_REVIEW)


@dataclass
class PolicyRule:
    id: str
    description: str
    match_tools: list[str]
    match_trust_levels: list[str]
    match_taint_tags: list[str]
    match_taint_tags_absent: list[str]
    outcome: PolicyOutcome
    reason: str
    enabled: bool = True

    def matches(self, tool_name: str, trust_level: TrustLevel, taint_tags: set[str]) -> bool:
        if not self.enabled:
            return False
        if self.match_tools != ["*"]:
            if not any(fnmatch.fnmatch(tool_name, pat) for pat in self.match_tools):
                return False
        if self.match_trust_levels != ["*"]:
            if trust_level.name not in self.match_trust_levels:
                return False
        if self.match_taint_tags:
            if not all(t in taint_tags for t in self.match_taint_tags):
                return False
        if self.match_taint_tags_absent:
            if any(t in taint_tags for t in self.match_taint_tags_absent):
                return False
        return True


class PolicyEngine:
    """
    Loads policy YAML files and evaluates capability requests.
    First matching rule wins. Default: deny if no rule matches.
    """

    def __init__(
        self,
        policy_files: list[Path] | None = None,
        *,
        dry_run: bool = False,
        default_outcome: PolicyOutcome = PolicyOutcome.DENY,
    ) -> None:
        self.dry_run = dry_run
        self.default_outcome = default_outcome
        self._rules: list[PolicyRule] = []

        if policy_files is None:
            policy_files = self._discover()

        for pf in policy_files:
            self._load(pf)

        log.info("PolicyEngine: %d rules loaded (dry_run=%s)", len(self._rules), dry_run)

    @staticmethod
    def _discover() -> list[Path]:
        if not POLICIES_DIR.exists():
            return []
        return sorted(POLICIES_DIR.glob("*.yaml")) + sorted(POLICIES_DIR.glob("*.yml"))

    def _load(self, path: Path) -> None:
        if not _YAML_AVAILABLE:
            log.warning("PyYAML not installed — skipping %s", path)
            return
        try:
            data = yaml.safe_load(path.read_text())
        except Exception as e:
            log.error("Failed to load policy %s: %s", path, e)
            return
        for raw in (data or {}).get("rules", []):
            try:
                self._rules.append(_parse_rule(raw))
            except Exception as e:
                log.error("Skipping bad rule %s in %s: %s", raw.get("id", "?"), path, e)

    def evaluate(self, tool_name: str, trust_level: TrustLevel, taint_tags: set[str]) -> PolicyDecision:
        for rule in self._rules:
            if rule.matches(tool_name, trust_level, taint_tags):
                decision = PolicyDecision(
                    outcome=rule.outcome, rule_id=rule.id,
                    reason=rule.reason, dry_run=self.dry_run,
                )
                if self.dry_run:
                    log.info("[DRY-RUN] %s → %s (rule=%s)", tool_name, rule.outcome.value, rule.id)
                return decision
        return PolicyDecision(
            outcome=self.default_outcome, rule_id="__default__",
            reason="No matching rule — default policy applied", dry_run=self.dry_run,
        )

    def add_rule(self, rule: PolicyRule) -> None:
        self._rules.append(rule)

    @property
    def rules(self) -> list[PolicyRule]:
        return list(self._rules)


def _parse_rule(raw: dict[str, Any]) -> PolicyRule:
    match = raw.get("match", {})
    tools = match.get("tools", ["*"])
    if isinstance(tools, str):
        tools = [tools]
    trust_levels = match.get("trust_levels", ["*"])
    if isinstance(trust_levels, str):
        trust_levels = [trust_levels]
    trust_levels = [str(t) for t in trust_levels]
    outcome_str = raw.get("outcome", "deny")
    try:
        outcome = PolicyOutcome(outcome_str)
    except ValueError:
        raise ValueError(f"Unknown outcome '{outcome_str}'")
    return PolicyRule(
        id=raw.get("id", "unnamed"),
        description=raw.get("description", ""),
        match_tools=tools,
        match_trust_levels=trust_levels,
        match_taint_tags=match.get("taint_tags", []),
        match_taint_tags_absent=match.get("taint_tags_absent", []),
        outcome=outcome,
        reason=raw.get("reason", raw.get("description", "")),
        enabled=raw.get("enabled", True),
    )


__all__ = ["PolicyOutcome", "PolicyDecision", "PolicyRule", "PolicyEngine", "POLICIES_DIR"]
