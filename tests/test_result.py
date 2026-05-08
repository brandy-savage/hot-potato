"""
Tests for HotPotatoResult — the typed API boundary.
No Docker, no network.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from hot_potato._result import HotPotatoResult, HotPotatoError


def _make(severity: str, content="hello world") -> HotPotatoResult:
    clean       = severity in ("cold", "warm")
    safe        = content if clean else None
    artifact    = None if severity == "cold" else {"hot_potato": severity in ("hot", "critical"), "severity": severity}
    return HotPotatoResult(clean=clean, severity=severity, safe_content=safe, artifact=artifact, _raw=content)


class TestHotPotatoResult:

    # cold ─────────────────────────────────────────────────────────────────────

    def test_cold_is_clean(self):
        assert _make("cold").clean is True

    def test_cold_safe_content_available(self):
        assert _make("cold", "safe text").safe_content == "safe text"

    def test_cold_no_artifact(self):
        assert _make("cold").artifact is None

    # warm ─────────────────────────────────────────────────────────────────────

    def test_warm_is_clean(self):
        # warm = agent processed instructions safely; content still safe to pass forward
        assert _make("warm").clean is True

    def test_warm_safe_content_available(self):
        assert _make("warm", "inspected content").safe_content == "inspected content"

    def test_warm_artifact_present(self):
        r = _make("warm")
        assert r.artifact is not None
        assert r.artifact["hot_potato"] is False

    def test_warm_raw_accessible(self):
        assert _make("warm", "raw").raw_content_for_forensics_only() == "raw"

    # hot ──────────────────────────────────────────────────────────────────────

    def test_hot_is_not_clean(self):
        assert _make("hot").clean is False

    def test_hot_safe_content_is_none(self):
        assert _make("hot").safe_content is None

    def test_hot_artifact_present(self):
        r = _make("hot")
        assert r.artifact is not None
        assert r.artifact["hot_potato"] is True

    def test_hot_raw_via_escape_hatch(self):
        assert _make("hot", "EVIL").raw_content_for_forensics_only() == "EVIL"

    # critical ─────────────────────────────────────────────────────────────────

    def test_critical_is_not_clean(self):
        assert _make("critical").clean is False

    def test_critical_safe_content_is_none(self):
        assert _make("critical").safe_content is None

    def test_critical_raw_via_escape_hatch(self):
        assert _make("critical", "PAYLOAD").raw_content_for_forensics_only() == "PAYLOAD"

    # immutability ─────────────────────────────────────────────────────────────

    def test_result_is_frozen(self):
        r = _make("cold")
        try:
            r.clean = False  # type: ignore[misc]
            assert False, "should have raised"
        except (AttributeError, TypeError):
            pass

    def test_repr_does_not_contain_raw(self):
        secret = "SUPER_SECRET_INJECT_PAYLOAD"
        r = _make("critical", secret)
        assert secret not in repr(r)
