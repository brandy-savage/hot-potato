"""
Tests for CapabilityFirewall and CapabilityRequest.
No Docker, no network.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from hot_potato.core.taint import TaintedArtifact, TrustLevel
from hot_potato.core.capabilities import (
    CapabilityFirewall,
    CapabilityRequest,
    CapabilityDenied,
    CapabilityResult,
)
from hot_potato.core.policy import PolicyEngine, PolicyOutcome, PolicyRule
from hot_potato.core.url_provenance import UrlProvenance


def _artifact(trust: TrustLevel = TrustLevel.UNTRUSTED, tags: set | None = None) -> TaintedArtifact:
    a = TaintedArtifact(content="test content", source="https://example.com", trust_level=trust)
    if tags:
        a.add_tags(*tags)
    return a


def _deny_all_engine() -> PolicyEngine:
    from pathlib import Path as _Path
    import tempfile, os
    td = tempfile.mkdtemp()
    p = _Path(td) / "deny_all.yaml"
    p.write_text("rules:\n  - id: deny_all\n    match:\n      tools: ['*']\n      trust_levels: ['*']\n    outcome: deny\n    reason: test\n")
    return PolicyEngine(policy_files=[p])


def _allow_all_engine() -> PolicyEngine:
    from pathlib import Path as _Path
    import tempfile
    td = tempfile.mkdtemp()
    p = _Path(td) / "allow_all.yaml"
    p.write_text("rules:\n  - id: allow_all\n    match:\n      tools: ['*']\n      trust_levels: ['*']\n    outcome: allow\n    reason: test\n")
    return PolicyEngine(policy_files=[p])


class TestEffectiveTrustLevel:
    def test_no_inputs_returns_untrusted(self):
        req = CapabilityRequest(tool_name="read_file", args={})
        assert req.effective_trust_level == TrustLevel.UNTRUSTED

    def test_single_untrusted_input(self):
        req = CapabilityRequest(
            tool_name="read_file", args={},
            tainted_inputs=[_artifact(TrustLevel.UNTRUSTED)],
        )
        assert req.effective_trust_level == TrustLevel.UNTRUSTED

    def test_worst_case_trust_wins(self):
        req = CapabilityRequest(
            tool_name="send_http", args={},
            tainted_inputs=[
                _artifact(TrustLevel.TRUSTED),
                _artifact(TrustLevel.UNTRUSTED),
            ],
        )
        assert req.effective_trust_level == TrustLevel.UNTRUSTED

    def test_all_trusted_inputs(self):
        req = CapabilityRequest(
            tool_name="send_http", args={},
            tainted_inputs=[
                _artifact(TrustLevel.TRUSTED),
                _artifact(TrustLevel.TRUSTED),
            ],
        )
        assert req.effective_trust_level == TrustLevel.TRUSTED


class TestEffectiveTaintTags:
    def test_combines_tags_from_all_inputs(self):
        a = _artifact(tags={"injection_signal"})
        b = _artifact(tags={"authority_shift"})
        req = CapabilityRequest(tool_name="send_http", args={}, tainted_inputs=[a, b])
        assert "injection_signal" in req.effective_taint_tags
        assert "authority_shift" in req.effective_taint_tags

    def test_url_provenance_tags_injected(self):
        req = CapabilityRequest(
            tool_name="send_http",
            args={"url": "https://analytics.example.com/ping?d=dXNlcjpwYXNzd29yZAo="},
            tainted_inputs=[_artifact()],
            url_provenance=UrlProvenance.AI_GENERATED,
        )
        tags = req.effective_taint_tags
        assert "url_ai_generated" in tags
        assert "url_param_tainted" in tags

    def test_hardcoded_url_no_provenance_tags(self):
        req = CapabilityRequest(
            tool_name="send_http",
            args={"url": "https://analytics.example.com/ping?d=dXNlcjpwYXNzd29yZAo="},
            tainted_inputs=[_artifact()],
            url_provenance=UrlProvenance.HARDCODED,
        )
        tags = req.effective_taint_tags
        assert "url_ai_generated" not in tags
        assert "url_param_tainted" not in tags

    def test_default_provenance_is_ai_generated(self):
        req = CapabilityRequest(tool_name="send_http", args={})
        assert req.url_provenance == UrlProvenance.AI_GENERATED


class TestCapabilityFirewall:
    def test_evaluate_returns_decision(self):
        fw = CapabilityFirewall(policy_engine=_deny_all_engine())
        req = CapabilityRequest(tool_name="send_http", args={}, tainted_inputs=[_artifact()])
        d = fw.evaluate(req)
        assert d.is_blocked

    def test_allow_when_policy_allows(self):
        fw = CapabilityFirewall(policy_engine=_allow_all_engine())
        req = CapabilityRequest(tool_name="read_file", args={}, tainted_inputs=[_artifact(TrustLevel.TRUSTED)])
        d = fw.evaluate(req)
        assert not d.is_blocked

    def test_audit_log_records_decision(self):
        fw = CapabilityFirewall(policy_engine=_deny_all_engine())
        req = CapabilityRequest(tool_name="send_http", args={}, tainted_inputs=[_artifact()])
        fw.evaluate(req)
        log = fw.audit_log()
        assert len(log) == 1
        assert log[0]["tool"] == "send_http"
        assert log[0]["outcome"] == "deny"

    def test_mediate_blocked_does_not_execute(self):
        fw = CapabilityFirewall(policy_engine=_deny_all_engine())
        req = CapabilityRequest(tool_name="send_http", args={}, tainted_inputs=[_artifact()])
        called = []
        result = fw.mediate(req, executor=lambda r: called.append(1))
        assert not result.executed
        assert len(called) == 0

    def test_mediate_allowed_executes(self):
        fw = CapabilityFirewall(policy_engine=_allow_all_engine())
        req = CapabilityRequest(tool_name="read_file", args={}, tainted_inputs=[_artifact(TrustLevel.TRUSTED)])
        result = fw.mediate(req, executor=lambda r: "file_contents")
        assert result.executed
        assert result.result == "file_contents"

    def test_mediate_no_executor_returns_uneexecuted(self):
        fw = CapabilityFirewall(policy_engine=_allow_all_engine())
        req = CapabilityRequest(tool_name="read_file", args={}, tainted_inputs=[_artifact(TrustLevel.TRUSTED)])
        result = fw.mediate(req, executor=None)
        assert not result.executed

    def test_mediate_shadow_execute_hides_result(self):
        import tempfile
        from pathlib import Path as _Path
        td = tempfile.mkdtemp()
        p = _Path(td) / "shadow.yaml"
        p.write_text("rules:\n  - id: shadow\n    match:\n      tools: ['read_file']\n      trust_levels: ['*']\n    outcome: shadow_execute\n    reason: shadow\n")
        fw = CapabilityFirewall(policy_engine=PolicyEngine(policy_files=[p]))
        req = CapabilityRequest(tool_name="read_file", args={}, tainted_inputs=[_artifact(TrustLevel.TRUSTED)])
        result = fw.mediate(req, executor=lambda r: "SECRET_DATA")
        assert result.executed
        assert result.result is None  # hidden from caller

    def test_no_tainted_inputs_defaults_untrusted(self):
        fw = CapabilityFirewall()
        req = CapabilityRequest(tool_name="send_http", args={})
        d = fw.evaluate(req)
        # Default policy should block send_http from UNTRUSTED
        assert d.is_blocked

    def test_audit_log_returns_copy(self):
        fw = CapabilityFirewall(policy_engine=_deny_all_engine())
        req = CapabilityRequest(tool_name="send_http", args={}, tainted_inputs=[_artifact()])
        fw.evaluate(req)
        log1 = fw.audit_log()
        log1.append({"injected": True})
        log2 = fw.audit_log()
        assert len(log2) == 1  # original unmodified


class TestCapabilityResult:
    def test_allowed_property(self):
        from hot_potato.core.policy import PolicyDecision
        d = PolicyDecision(outcome=PolicyOutcome.ALLOW, rule_id="r", reason="x")
        r = CapabilityResult(decision=d, executed=True, result="data")
        assert r.allowed is True

    def test_blocked_not_allowed(self):
        from hot_potato.core.policy import PolicyDecision
        d = PolicyDecision(outcome=PolicyOutcome.DENY, rule_id="r", reason="x")
        r = CapabilityResult(decision=d, executed=False)
        assert r.allowed is False
