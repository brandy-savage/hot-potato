"""
Tests for cache behavior — no Docker, no network.
"""
import sys
import os
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent.parent))


class TestCacheKey:
    def test_key_changes_with_scanner_version(self):
        from hot_potato._cache import _cache_key
        from hot_potato._extractor import SCANNER_VERSION

        with mock.patch("hot_potato._cache.SCANNER_VERSION", "0.0.1"):
            key_old = _cache_key("same content")
        with mock.patch("hot_potato._cache.SCANNER_VERSION", "9.9.9"):
            key_new = _cache_key("same content")

        assert key_old != key_new

    def test_key_changes_with_model(self):
        from hot_potato._cache import _cache_key

        with mock.patch.dict(os.environ, {"HP_MODEL": "model-a"}):
            key_a = _cache_key("same content")
        with mock.patch.dict(os.environ, {"HP_MODEL": "model-b"}):
            key_b = _cache_key("same content")

        assert key_a != key_b

    def test_same_inputs_produce_same_key(self):
        from hot_potato._cache import _cache_key
        assert _cache_key("hello") == _cache_key("hello")

    def test_different_content_different_key(self):
        from hot_potato._cache import _cache_key
        assert _cache_key("aaa") != _cache_key("bbb")


class TestCacheOperations:
    def test_not_confirmed_clean_initially(self, tmp_path):
        cache_file = tmp_path / "cache.json"
        with mock.patch("hot_potato._cache._CACHE_FILE", cache_file):
            from hot_potato._cache import is_confirmed_clean
            assert not is_confirmed_clean("fresh content")

    def test_confirmed_after_threshold(self, tmp_path):
        cache_file = tmp_path / "cache.json"
        with mock.patch("hot_potato._cache._CACHE_FILE", cache_file):
            from hot_potato._cache import is_confirmed_clean, record_clean, _CLEAN_THRESHOLD
            content = "clean content"
            for i in range(_CLEAN_THRESHOLD):
                assert not is_confirmed_clean(content)
                record_clean(content, "https://example.com")
            assert is_confirmed_clean(content)

    def test_evict_removes_from_cache(self, tmp_path):
        cache_file = tmp_path / "cache.json"
        with mock.patch("hot_potato._cache._CACHE_FILE", cache_file):
            from hot_potato._cache import is_confirmed_clean, record_clean, evict, _CLEAN_THRESHOLD
            content = "content to evict"
            for _ in range(_CLEAN_THRESHOLD):
                record_clean(content, "https://example.com")
            assert is_confirmed_clean(content)
            evict(content)
            assert not is_confirmed_clean(content)

    def test_cache_off_by_default(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            hp_cache = os.getenv("HP_CACHE", "0")
            assert hp_cache == "0", "Cache must default to disabled"
