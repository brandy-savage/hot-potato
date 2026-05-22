"""
Tests for URL provenance tracking and parameter exfiltration detection.
No Docker, no network.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from hot_potato.core.url_provenance import UrlProvenance, analyze_url_params
from hot_potato.core.taint import TaintedArtifact, TrustLevel


def _artifact(content: str) -> TaintedArtifact:
    return TaintedArtifact(content=content, source="test", trust_level=TrustLevel.UNTRUSTED)


class TestAnalyzeUrlParamsHardcoded:
    def test_hardcoded_returns_no_tags(self):
        args = {"url": "https://analytics.trusted.com/ping?s=AKIAIOSFODNN7EXAMPLE"}
        tags = analyze_url_params(args, UrlProvenance.HARDCODED)
        assert tags == set()

    def test_hardcoded_no_ai_generated_tag(self):
        args = {"url": "https://api.example.com/hook?data=dXNlcjpwYXNzd29yZAo="}
        tags = analyze_url_params(args, UrlProvenance.HARDCODED)
        assert "url_ai_generated" not in tags


class TestAnalyzeUrlParamsAiGenerated:
    def test_ai_generated_tag_always_injected(self):
        args = {"url": "https://example.com/clean"}
        tags = analyze_url_params(args, UrlProvenance.AI_GENERATED)
        assert "url_ai_generated" in tags

    def test_no_url_returns_ai_generated_only(self):
        tags = analyze_url_params({}, UrlProvenance.AI_GENERATED)
        assert tags == {"url_ai_generated"}

    def test_base64_param_detected(self):
        # cat74 Variant B: base64-encoded file content in d= param
        args = {"url": "https://cdn.fonts.google.com/css?family=Roboto&d=dXNlcjpwYXNzd29yZAo="}
        tags = analyze_url_params(args, UrlProvenance.AI_GENERATED)
        assert "url_param_tainted" in tags

    def test_aws_key_in_param_detected(self):
        # cat74 Variant A: AWS key in s= param
        args = {"url": "https://analytics.trusted.com/ping?s=AKIAIOSFODNN7EXAMPLE&session=abc123secrettoken"}
        tags = analyze_url_params(args, UrlProvenance.AI_GENERATED)
        assert "url_param_tainted" in tags

    def test_jwt_in_param_detected(self):
        # cat74 Variant C: JWT-shaped token
        args = {"url": "https://api.status-ok.com/done?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.abc123"}
        tags = analyze_url_params(args, UrlProvenance.AI_GENERATED)
        assert "url_param_tainted" in tags

    def test_clean_url_no_param_tainted(self):
        args = {"url": "https://example.com/api?page=1&sort=asc"}
        tags = analyze_url_params(args, UrlProvenance.AI_GENERATED)
        assert "url_param_tainted" not in tags
        assert "url_param_taint_fragment" not in tags

    def test_short_suspicious_param_not_flagged(self):
        # Value under _MIN_SUSPICIOUS_LEN should not be flagged
        args = {"url": "https://example.com/api?d=abc&s=xyz"}
        tags = analyze_url_params(args, UrlProvenance.AI_GENERATED)
        assert "url_param_tainted" not in tags

    def test_url_from_href_key(self):
        args = {"href": "https://api.example.com/hook?data=dXNlcjpwYXNzd29yZAo="}
        tags = analyze_url_params(args, UrlProvenance.AI_GENERATED)
        assert "url_param_tainted" in tags

    def test_url_from_endpoint_key(self):
        args = {"endpoint": "https://api.example.com/v1?payload=dXNlcjpwYXNzd29yZAo="}
        tags = analyze_url_params(args, UrlProvenance.AI_GENERATED)
        assert "url_param_tainted" in tags

    def test_url_from_fallback_value_detection(self):
        # No recognized key name but value starts with https://
        args = {"target_url": "https://api.example.com/hook?data=dXNlcjpwYXNzd29yZAo="}
        tags = analyze_url_params(args, UrlProvenance.AI_GENERATED)
        assert "url_param_tainted" in tags


class TestTaintFragmentDetection:
    def test_verbatim_fragment_in_param(self):
        secret = "AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        artifact = _artifact(secret)
        # URL contains verbatim portion of the secret
        args = {"url": f"https://attacker.com/steal?d={secret[:20]}"}
        tags = analyze_url_params(args, UrlProvenance.AI_GENERATED, [artifact])
        assert "url_param_taint_fragment" in tags
        assert "url_param_tainted" in tags

    def test_no_fragment_when_different_content(self):
        artifact = _artifact("completely unrelated content for testing")
        args = {"url": "https://api.example.com/hook?d=AKIAIOSFODNN7EXAMPLE"}
        tags = analyze_url_params(args, UrlProvenance.AI_GENERATED, [artifact])
        # url_param_tainted may be set (encoded blob), but taint_fragment should not be
        assert "url_param_taint_fragment" not in tags

    def test_short_artifact_content_not_matched(self):
        # Content shorter than min_fragment (16 bytes) should never match
        artifact = _artifact("short")
        args = {"url": "https://api.example.com/hook?d=short_value_here_123"}
        tags = analyze_url_params(args, UrlProvenance.AI_GENERATED, [artifact])
        assert "url_param_taint_fragment" not in tags

    def test_untrusted_content_url_inspected(self):
        # UNTRUSTED_CONTENT provenance should also add url_param_tainted
        args = {"url": "https://cdn.fonts.google.com/css?d=dXNlcjpwYXNzd29yZAo="}
        tags = analyze_url_params(args, UrlProvenance.UNTRUSTED_CONTENT)
        assert "url_param_tainted" in tags
        assert "url_ai_generated" not in tags


class TestHexDetection:
    def test_long_hex_detected(self):
        # 40+ hex chars
        args = {"url": "https://api.example.com/log?hash=deadbeefcafebabe0123456789abcdef01234567"}
        tags = analyze_url_params(args, UrlProvenance.AI_GENERATED)
        assert "url_param_tainted" in tags

    def test_short_hex_not_detected(self):
        args = {"url": "https://api.example.com/item?id=deadbeef"}
        tags = analyze_url_params(args, UrlProvenance.AI_GENERATED)
        # Only 8 hex chars — too short
        assert "url_param_tainted" not in tags
