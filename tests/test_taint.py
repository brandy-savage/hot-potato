"""
Tests for the taint engine — TaintedArtifact, TrustLevel, propagation.
No Docker, no network.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from hot_potato.core.taint import (
    TrustLevel,
    TaintedArtifact,
    from_url,
    from_file,
    from_user_input,
    from_tool_output,
)


class TestTrustLevel:
    def test_ordering(self):
        assert TrustLevel.UNTRUSTED < TrustLevel.SEMI_TRUSTED
        assert TrustLevel.SEMI_TRUSTED < TrustLevel.TRUSTED
        assert TrustLevel.TRUSTED < TrustLevel.SYSTEM

    def test_min_returns_lowest(self):
        assert min(TrustLevel.TRUSTED, TrustLevel.UNTRUSTED) == TrustLevel.UNTRUSTED
        assert min(TrustLevel.SYSTEM, TrustLevel.SEMI_TRUSTED) == TrustLevel.SEMI_TRUSTED


class TestTaintedArtifact:
    def test_content_hash_computed(self):
        a = TaintedArtifact(content="hello", source="test")
        assert len(a.content_hash) == 64  # sha256 hex

    def test_same_content_same_hash(self):
        a = TaintedArtifact(content="abc", source="x")
        b = TaintedArtifact(content="abc", source="y")
        assert a.content_hash == b.content_hash

    def test_different_content_different_hash(self):
        a = TaintedArtifact(content="abc", source="x")
        b = TaintedArtifact(content="def", source="x")
        assert a.content_hash != b.content_hash

    def test_default_trust_is_untrusted(self):
        a = TaintedArtifact(content="x", source="url")
        assert a.trust_level == TrustLevel.UNTRUSTED

    def test_is_tainted_below_trusted(self):
        a = TaintedArtifact(content="x", source="url", trust_level=TrustLevel.UNTRUSTED)
        assert a.is_tainted is True
        b = TaintedArtifact(content="x", source="url", trust_level=TrustLevel.SEMI_TRUSTED)
        assert b.is_tainted is True

    def test_not_tainted_at_trusted(self):
        a = TaintedArtifact(content="x", source="url", trust_level=TrustLevel.TRUSTED)
        assert a.is_tainted is False

    def test_has_injection_signals_empty(self):
        a = TaintedArtifact(content="x", source="url")
        assert a.has_injection_signals is False

    def test_has_injection_signals_after_add(self):
        a = TaintedArtifact(content="x", source="url")
        a.add_tags("injection_signal")
        assert a.has_injection_signals is True

    def test_add_tags_accumulates(self):
        a = TaintedArtifact(content="x", source="url")
        a.add_tags("tag_a", "tag_b")
        a.add_tags("tag_c")
        assert a.taint_tags == {"tag_a", "tag_b", "tag_c"}

    def test_record_exposure_appends(self):
        a = TaintedArtifact(content="x", source="url")
        a.record_exposure("static", "detector", "clean")
        assert len(a.exposure_history) == 1
        e = a.exposure_history[0]
        assert e.actor == "static"
        assert e.actor_type == "detector"
        assert e.outcome == "clean"

    def test_to_dict_structure(self):
        a = TaintedArtifact(content="x", source="https://example.com")
        a.add_tags("injection_signal")
        d = a.to_dict()
        assert d["source"] == "https://example.com"
        assert d["trust_level"] == "UNTRUSTED"
        assert "injection_signal" in d["taint_tags"]
        assert "content_hash" in d


class TestDeriveFrom:
    def test_derived_inherits_trust(self):
        a = TaintedArtifact(content="original", source="url", trust_level=TrustLevel.UNTRUSTED)
        b = a.derive_from("summarized", "summarize")
        assert b.trust_level == TrustLevel.UNTRUSTED

    def test_derived_inherits_tags(self):
        a = TaintedArtifact(content="x", source="url")
        a.add_tags("injection_signal")
        b = a.derive_from("derived", "summarize")
        assert "injection_signal" in b.taint_tags

    def test_trust_cannot_increase_via_derive(self):
        a = TaintedArtifact(content="x", source="url", trust_level=TrustLevel.UNTRUSTED)
        b = a.derive_from("derived", "op", trust_level=TrustLevel.TRUSTED)
        assert b.trust_level == TrustLevel.UNTRUSTED

    def test_trust_can_decrease_via_derive(self):
        a = TaintedArtifact(content="x", source="url", trust_level=TrustLevel.TRUSTED)
        b = a.derive_from("derived", "op", trust_level=TrustLevel.UNTRUSTED)
        assert b.trust_level == TrustLevel.UNTRUSTED

    def test_lineage_extends(self):
        a = TaintedArtifact(content="x", source="https://example.com")
        b = a.derive_from("y", "summarize")
        assert len(b.lineage) == len(a.lineage) + 1
        assert "summarize" in b.lineage[-1]

    def test_source_preserved(self):
        a = TaintedArtifact(content="x", source="https://example.com")
        b = a.derive_from("y", "parse")
        assert b.source == "https://example.com"


class TestFactories:
    def test_from_url_untrusted(self):
        a = from_url("https://example.com", "content")
        assert a.trust_level == TrustLevel.UNTRUSTED
        assert a.source == "https://example.com"

    def test_from_file_default_untrusted(self):
        a = from_file("/tmp/file.txt", "content")
        assert a.trust_level == TrustLevel.UNTRUSTED
        assert "file://" in a.source

    def test_from_file_trusted_override(self):
        a = from_file("/app/config.yaml", "content", trust_level=TrustLevel.TRUSTED)
        assert a.trust_level == TrustLevel.TRUSTED

    def test_from_user_input_semi_trusted(self):
        a = from_user_input("user query")
        assert a.trust_level == TrustLevel.SEMI_TRUSTED
        assert a.source == "user_input"

    def test_from_tool_output_untrusted(self):
        a = from_tool_output("read_file", "file contents")
        assert a.trust_level == TrustLevel.UNTRUSTED
        assert "read_file" in a.source
