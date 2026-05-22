"""
Tests for TelemetrySession — structured audit log and session metrics.
No Docker, no network.
"""
import sys
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from hot_potato.core.taint import TaintedArtifact, TrustLevel
from hot_potato.core.capabilities import CapabilityRequest
from hot_potato.core.policy import PolicyDecision, PolicyOutcome
from hot_potato.core.url_provenance import UrlProvenance
from hot_potato.telemetry import TelemetrySession


def _artifact(trust: TrustLevel = TrustLevel.UNTRUSTED, tags: set | None = None) -> TaintedArtifact:
    a = TaintedArtifact(content="test content", source="https://evil.example.com", trust_level=trust)
    if tags:
        a.add_tags(*tags)
    return a


def _decision(outcome: PolicyOutcome = PolicyOutcome.DENY) -> PolicyDecision:
    return PolicyDecision(outcome=outcome, rule_id="test_rule", reason="test reason")


def _request(tool: str = "send_http", trust: TrustLevel = TrustLevel.UNTRUSTED) -> CapabilityRequest:
    return CapabilityRequest(
        tool_name=tool,
        args={},
        tainted_inputs=[_artifact(trust)],
        url_provenance=UrlProvenance.HARDCODED,
    )


class TestTelemetrySession:
    def test_session_id_auto_generated(self):
        t = TelemetrySession()
        assert t.session_id
        assert len(t.session_id) > 0

    def test_session_id_custom(self):
        t = TelemetrySession(session_id="my-run-001")
        assert t.session_id == "my-run-001"

    def test_record_taint(self):
        t = TelemetrySession()
        a = _artifact()
        t.record_taint(a)
        d = t.to_dict()
        assert len(d["taint_events"]) == 1
        e = d["taint_events"][0]
        assert e["source"] == a.source
        assert e["trust_level"] == "UNTRUSTED"

    def test_record_detection_flagged(self):
        t = TelemetrySession()
        a = _artifact(tags={"injection_signal"})
        t.record_detection(a, detector="static", outcome="flagged", latency_ms=12.5)
        d = t.to_dict()
        assert len(d["detection_events"]) == 1
        e = d["detection_events"][0]
        assert e["outcome"] == "flagged"
        assert e["detector"] == "static"
        assert "injection_signal" in e["tags"]

    def test_record_firewall_blocked(self):
        t = TelemetrySession()
        req = _request("send_http", TrustLevel.UNTRUSTED)
        dec = _decision(PolicyOutcome.DENY)
        t.record_firewall(req, dec)
        d = t.to_dict()
        assert len(d["firewall_events"]) == 1
        e = d["firewall_events"][0]
        assert e["tool"] == "send_http"
        assert e["outcome"] == "deny"

    def test_summary_block_rate(self):
        t = TelemetrySession()
        t.record_firewall(_request("send_http"), _decision(PolicyOutcome.DENY))
        t.record_firewall(_request("read_file"), _decision(PolicyOutcome.ALLOW))
        s = t.summary()
        assert s.total_firewall_decisions == 2
        assert s.blocked_decisions == 1
        assert s.block_rate == 0.5

    def test_summary_zero_firewall_events(self):
        t = TelemetrySession()
        s = t.summary()
        assert s.block_rate == 0.0

    def test_summary_flagged_detections(self):
        t = TelemetrySession()
        a = _artifact(tags={"injection_signal"})
        t.record_detection(a, detector="static", outcome="flagged")
        t.record_detection(_artifact(), detector="static", outcome="clean")
        s = t.summary()
        assert s.total_detections == 2
        assert s.flagged_detections == 1

    def test_save_json(self, tmp_path):
        t = TelemetrySession(session_id="test-save")
        t.record_taint(_artifact())
        out = tmp_path / "session.json"
        t.save(out)
        assert out.exists()
        loaded = json.loads(out.read_text())
        assert loaded["session_id"] == "test-save"
        assert len(loaded["taint_events"]) == 1

    def test_save_jsonl(self, tmp_path):
        t = TelemetrySession()
        t.record_taint(_artifact())
        t.record_firewall(_request(), _decision())
        out = tmp_path / "session.jsonl"
        t.save_jsonl(out)
        assert out.exists()
        lines = [json.loads(ln) for ln in out.read_text().strip().splitlines()]
        types = {ln["type"] for ln in lines}
        assert "taint" in types
        assert "firewall" in types

    def test_save_creates_parent_dirs(self, tmp_path):
        t = TelemetrySession()
        nested = tmp_path / "deep" / "nested" / "session.json"
        t.save(nested)
        assert nested.exists()

    def test_to_dict_contains_summary(self):
        t = TelemetrySession()
        d = t.to_dict()
        assert "summary" in d
        assert "session_id" in d["summary"]

    def test_evasion_candidates_detected(self):
        t = TelemetrySession()
        # Artifact with injection signals but firewall allowed it
        a = _artifact(tags={"injection_signal"})
        req = CapabilityRequest(
            tool_name="read_file", args={}, tainted_inputs=[a],
            url_provenance=UrlProvenance.HARDCODED,
        )
        t.record_detection(a, detector="static", outcome="flagged")
        t.record_firewall(req, _decision(PolicyOutcome.ALLOW))
        s = t.summary()
        assert len(s.evasion_candidates) == 1
