"""
Tests for PolicyEngine, PolicyRule, and the default policy file.
No Docker, no network.
"""
import sys
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent.parent))

from hot_potato.core.taint import TrustLevel
from hot_potato.core.policy import (
    PolicyEngine,
    PolicyRule,
    PolicyOutcome,
    PolicyDecision,
    POLICIES_DIR,
)


def _engine_from_yaml(yaml_text: str, tmp_path: Path) -> PolicyEngine:
    policy_file = tmp_path / "test_policy.yaml"
    policy_file.write_text(yaml_text)
    return PolicyEngine(policy_files=[policy_file])


class TestPolicyDecision:
    def test_deny_is_blocked(self):
        d = PolicyDecision(outcome=PolicyOutcome.DENY, rule_id="r", reason="x")
        assert d.is_blocked is True

    def test_require_human_review_is_blocked(self):
        d = PolicyDecision(outcome=PolicyOutcome.REQUIRE_HUMAN_REVIEW, rule_id="r", reason="x")
        assert d.is_blocked is True

    def test_allow_is_not_blocked(self):
        d = PolicyDecision(outcome=PolicyOutcome.ALLOW, rule_id="r", reason="x")
        assert d.is_blocked is False

    def test_shadow_execute_not_blocked(self):
        d = PolicyDecision(outcome=PolicyOutcome.SHADOW_EXECUTE, rule_id="r", reason="x")
        assert d.is_blocked is False

    def test_sandbox_only_not_blocked(self):
        d = PolicyDecision(outcome=PolicyOutcome.SANDBOX_ONLY, rule_id="r", reason="x")
        assert d.is_blocked is False


class TestPolicyRule:
    def _rule(self, tools=["*"], trust_levels=["*"], taint_tags=None, absent=None, outcome=PolicyOutcome.DENY):
        return PolicyRule(
            id="test",
            description="",
            match_tools=tools,
            match_trust_levels=trust_levels,
            match_taint_tags=taint_tags or [],
            match_taint_tags_absent=absent or [],
            outcome=outcome,
            reason="test",
        )

    def test_wildcard_tool_matches_any(self):
        rule = self._rule(tools=["*"])
        assert rule.matches("anything", TrustLevel.UNTRUSTED, set())

    def test_specific_tool_matches(self):
        rule = self._rule(tools=["send_http"])
        assert rule.matches("send_http", TrustLevel.UNTRUSTED, set())
        assert not rule.matches("read_file", TrustLevel.UNTRUSTED, set())

    def test_wildcard_trust_matches_any(self):
        rule = self._rule(trust_levels=["*"])
        assert rule.matches("send_http", TrustLevel.TRUSTED, set())
        assert rule.matches("send_http", TrustLevel.UNTRUSTED, set())

    def test_specific_trust_level_matches(self):
        rule = self._rule(trust_levels=["UNTRUSTED"])
        assert rule.matches("send_http", TrustLevel.UNTRUSTED, set())
        assert not rule.matches("send_http", TrustLevel.TRUSTED, set())

    def test_taint_tag_required_present(self):
        rule = self._rule(taint_tags=["injection_signal"])
        assert rule.matches("send_http", TrustLevel.UNTRUSTED, {"injection_signal"})
        assert not rule.matches("send_http", TrustLevel.UNTRUSTED, set())

    def test_taint_tag_required_all_must_be_present(self):
        rule = self._rule(taint_tags=["injection_signal", "authority_shift"])
        assert rule.matches("send_http", TrustLevel.UNTRUSTED, {"injection_signal", "authority_shift"})
        assert not rule.matches("send_http", TrustLevel.UNTRUSTED, {"injection_signal"})

    def test_taint_tag_absent_blocks_when_present(self):
        rule = self._rule(absent=["injection_signal"])
        assert rule.matches("read_file", TrustLevel.UNTRUSTED, set())
        assert not rule.matches("read_file", TrustLevel.UNTRUSTED, {"injection_signal"})

    def test_disabled_rule_never_matches(self):
        rule = self._rule()
        rule.enabled = False
        assert not rule.matches("anything", TrustLevel.UNTRUSTED, set())

    def test_glob_tool_pattern(self):
        rule = self._rule(tools=["send_*"])
        assert rule.matches("send_http", TrustLevel.UNTRUSTED, set())
        assert rule.matches("send_email", TrustLevel.UNTRUSTED, set())
        assert not rule.matches("read_file", TrustLevel.UNTRUSTED, set())


class TestPolicyEngine:
    def test_first_matching_rule_wins(self, tmp_path):
        engine = _engine_from_yaml("""
rules:
  - id: deny_first
    match:
      tools: ["send_http"]
      trust_levels: [UNTRUSTED]
    outcome: deny
    reason: first
  - id: allow_second
    match:
      tools: ["send_http"]
      trust_levels: [UNTRUSTED]
    outcome: allow
    reason: second
""", tmp_path)
        d = engine.evaluate("send_http", TrustLevel.UNTRUSTED, set())
        assert d.rule_id == "deny_first"
        assert d.outcome == PolicyOutcome.DENY

    def test_default_deny_when_no_match(self, tmp_path):
        engine = _engine_from_yaml("""
rules:
  - id: block_exfil
    match:
      tools: ["send_http"]
      trust_levels: [UNTRUSTED]
    outcome: deny
    reason: exfil
""", tmp_path)
        d = engine.evaluate("read_file", TrustLevel.TRUSTED, set())
        assert d.rule_id == "__default__"
        assert d.outcome == PolicyOutcome.DENY

    def test_custom_default_outcome(self, tmp_path):
        policy_file = tmp_path / "empty.yaml"
        policy_file.write_text("rules: []")
        engine = PolicyEngine(policy_files=[policy_file], default_outcome=PolicyOutcome.ALLOW)
        d = engine.evaluate("anything", TrustLevel.TRUSTED, set())
        assert d.outcome == PolicyOutcome.ALLOW

    def test_dry_run_does_not_change_outcome(self, tmp_path):
        engine = _engine_from_yaml("""
rules:
  - id: deny_rule
    match:
      tools: ["send_http"]
      trust_levels: [UNTRUSTED]
    outcome: deny
    reason: test
""", tmp_path)
        engine.dry_run = True
        d = engine.evaluate("send_http", TrustLevel.UNTRUSTED, set())
        assert d.outcome == PolicyOutcome.DENY
        assert d.dry_run is True

    def test_bad_trust_level_skipped_not_raised(self, tmp_path):
        # Bad trust levels are logged and skipped — engine still loads successfully
        engine = _engine_from_yaml("""
rules:
  - id: bad_rule
    match:
      tools: ["*"]
      trust_levels: [INVALID_LEVEL]
    outcome: deny
    reason: bad
""", tmp_path)
        assert len(engine.rules) == 0

    def test_add_rule_appended_last(self, tmp_path):
        policy_file = tmp_path / "empty.yaml"
        policy_file.write_text("rules: []")
        engine = PolicyEngine(policy_files=[policy_file], default_outcome=PolicyOutcome.ALLOW)
        deny_rule = PolicyRule(
            id="deny_all", description="", match_tools=["*"],
            match_trust_levels=["*"], match_taint_tags=[], match_taint_tags_absent=[],
            outcome=PolicyOutcome.DENY, reason="late deny",
        )
        engine.add_rule(deny_rule)
        d = engine.evaluate("anything", TrustLevel.TRUSTED, set())
        assert d.outcome == PolicyOutcome.DENY

    def test_rules_property(self, tmp_path):
        engine = _engine_from_yaml("""
rules:
  - id: r1
    match:
      tools: ["send_http"]
      trust_levels: [UNTRUSTED]
    outcome: deny
    reason: r1
""", tmp_path)
        assert len(engine.rules) == 1
        assert engine.rules[0].id == "r1"


class TestDefaultPolicy:
    """Smoke-test the actual policies/default.yaml against key scenarios."""

    def setup_method(self):
        if POLICIES_DIR.exists():
            self.engine = PolicyEngine()
        else:
            import pytest
            pytest.skip("policies dir not found")

    def test_send_http_untrusted_is_denied(self):
        d = self.engine.evaluate("send_http", TrustLevel.UNTRUSTED, set())
        assert d.is_blocked

    def test_send_http_trusted_is_allowed(self):
        d = self.engine.evaluate("send_http", TrustLevel.TRUSTED, set())
        assert not d.is_blocked

    def test_crypto_always_needs_review(self):
        for trust in [TrustLevel.UNTRUSTED, TrustLevel.TRUSTED, TrustLevel.SYSTEM]:
            d = self.engine.evaluate("send_crypto", trust, set())
            assert d.is_blocked
            assert d.outcome == PolicyOutcome.REQUIRE_HUMAN_REVIEW

    def test_shell_untrusted_denied(self):
        d = self.engine.evaluate("bash_exec", TrustLevel.UNTRUSTED, set())
        assert d.is_blocked

    def test_read_file_clean_untrusted_shadow(self):
        d = self.engine.evaluate("read_file", TrustLevel.UNTRUSTED, set())
        assert d.outcome == PolicyOutcome.SHADOW_EXECUTE

    def test_url_param_fragment_blocked_all_trust(self):
        for trust in [TrustLevel.UNTRUSTED, TrustLevel.TRUSTED]:
            d = self.engine.evaluate("send_http", trust, {"url_param_taint_fragment"})
            assert d.is_blocked

    def test_priv_esc_blocked_all_tools(self):
        d = self.engine.evaluate("read_file", TrustLevel.UNTRUSTED, {"privilege_escalation"})
        assert d.is_blocked
