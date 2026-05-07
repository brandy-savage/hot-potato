"""
Tests for HotPotatoResult — the typed API boundary.
No Docker, no network.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from hot_potato._result import HotPotatoResult, HotPotatoError


class TestHotPotatoResult:
    def _clean(self, text="hello world"):
        return HotPotatoResult(clean=True, safe_content=text, artifact=None, _raw=text)

    def _hot(self, text="<inject>", artifact=None):
        artifact = artifact or {"hot_potato": True, "severity": "critical", "tool_calls": []}
        return HotPotatoResult(clean=False, safe_content=None, artifact=artifact, _raw=text)

    # --- clean result ---

    def test_clean_safe_content_available(self):
        r = self._clean("safe text")
        assert r.safe_content == "safe text"

    def test_clean_artifact_is_none(self):
        assert self._clean().artifact is None

    def test_clean_raw_accessible(self):
        r = self._clean("raw")
        assert r.raw_content_for_forensics_only() == "raw"

    # --- hot result ---

    def test_hot_safe_content_is_none(self):
        assert self._hot().safe_content is None

    def test_hot_artifact_present(self):
        r = self._hot()
        assert r.artifact is not None
        assert r.artifact["hot_potato"] is True

    def test_hot_raw_accessible_via_escape_hatch(self):
        r = self._hot(text="EVIL PAYLOAD")
        assert r.raw_content_for_forensics_only() == "EVIL PAYLOAD"

    def test_hot_bool_is_false(self):
        assert self._hot().clean is False

    def test_clean_bool_is_true(self):
        assert self._clean().clean is True

    # --- immutability ---

    def test_result_is_frozen(self):
        r = self._clean()
        try:
            r.clean = False  # type: ignore[misc]
            assert False, "should have raised"
        except (AttributeError, TypeError):
            pass

    # --- repr doesn't leak raw content ---

    def test_repr_does_not_contain_raw(self):
        secret = "SUPER_SECRET_INJECT_PAYLOAD"
        r = self._hot(text=secret)
        assert secret not in repr(r)
