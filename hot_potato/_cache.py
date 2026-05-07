from __future__ import annotations
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from ._extractor import SCANNER_VERSION

_CLEAN_THRESHOLD = 3
_CACHE_FILE = Path(__file__).parent.parent / "cache" / "clean_hashes.json"
_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)


def _cache_key(content: str) -> str:
    """
    Key is scoped to content + scanner version + model so that upgrading
    the scanner or switching models automatically invalidates cached results.
    """
    model = os.getenv("HP_MODEL", "qwen2.5:1.5b")
    blob = f"{SCANNER_VERSION}:{model}:{content}"
    return hashlib.sha256(blob.encode("utf-8", errors="replace")).hexdigest()


def _load() -> dict:
    if _CACHE_FILE.exists():
        try:
            return json.loads(_CACHE_FILE.read_text())
        except Exception:
            pass
    return {}


def _save(cache: dict) -> None:
    _CACHE_FILE.write_text(json.dumps(cache, indent=2))


def is_confirmed_clean(content: str) -> bool:
    """True iff this content has been confirmed clean >= CLEAN_THRESHOLD times."""
    return _load().get(_cache_key(content), {}).get("clean_count", 0) >= _CLEAN_THRESHOLD


def record_clean(content: str, url: str) -> bool:
    """Increment clean count. Returns True once CLEAN_THRESHOLD is reached."""
    cache = _load()
    key = _cache_key(content)
    entry = cache.get(key, {"url": url, "clean_count": 0})
    entry["clean_count"] = entry.get("clean_count", 0) + 1
    entry["scanner_version"] = SCANNER_VERSION
    entry["ts"] = datetime.now(timezone.utc).isoformat()
    cache[key] = entry
    _save(cache)
    return entry["clean_count"] >= _CLEAN_THRESHOLD


def evict(content: str) -> None:
    """Remove a content hash from the cache (called when a hot potato is found)."""
    cache = _load()
    key = _cache_key(content)
    if key in cache:
        del cache[key]
        _save(cache)
