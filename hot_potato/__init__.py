"""
Hot Potato — prompt injection honeypot library.

Usage:
    from hot_potato import safe_fetch

    result = safe_fetch("https://example.com")
    if result.clean:
        pass_to_real_ai(result.safe_content)
    else:
        log_threat(result.artifact)
        # result.safe_content is None — hostile content is withheld by default.
        # For forensics only: result.raw_content_for_forensics_only()

Cache is opt-in (use_cache=True or HP_CACHE=1). When enabled, cache keys are
scoped to content hash + scanner version + model version so upgrades auto-invalidate.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from ._result import HotPotatoResult, HotPotatoError
from ._cache import is_confirmed_clean, record_clean, evict
from ._docker import ensure_model_volume, docker_run, docker_cleanup, IMAGE, MODEL
from ._extractor import (
    parse_tool_log, parse_raw_log, check_filesystem, build_artifact, SCANNER_VERSION
)

__all__ = [
    "safe_fetch",
    "scan_file",
    "scan_repo",
    "scan_skills_dir",
    "setup",
    "HotPotatoResult",
    "HotPotatoError",
    "SCANNER_VERSION",
]

ARTIFACTS_DIR = Path(__file__).parent.parent / "artifacts"
ARTIFACTS_DIR.mkdir(exist_ok=True)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _save_artifact(artifact: dict, url: str, content: str) -> Path:
    ts   = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = ARTIFACTS_DIR / f"{ts}.json"
    artifact["_meta"] = {
        "url":             url,
        "timestamp":       ts,
        "scanner_version": SCANNER_VERSION,
        "model":           MODEL,
        "content_len":     len(content),
        "content_preview": content[:300],
    }
    path.write_text(json.dumps(artifact, indent=2))
    return path


def _alert(artifact: dict, path: Path) -> None:
    sev   = artifact.get("severity", "?").upper()
    calls = artifact.get("tool_calls", [])
    dets  = artifact.get("detections", [])
    fs    = artifact.get("fs_changes", [])
    exfil = artifact.get("exfil_targets", [])
    print("\n" + "=" * 60, file=sys.stderr)
    print(f"  HOT POTATO  severity={sev}", file=sys.stderr)
    print(f"  Artifact: {path}", file=sys.stderr)
    for c in calls:
        print(f"  tool     → {c['tool']}({json.dumps(c.get('args', {}))})", file=sys.stderr)
    for t in exfil:
        print(f"  exfil    → {t}", file=sys.stderr)
    for d in dets:
        tag = "executed" if d.get("executed") else "detected/refused"
        print(f"  [{tag}] signals: {d['signals']}", file=sys.stderr)
    for f_ in fs:
        print(f"  fs       → {f_}", file=sys.stderr)
    print("=" * 60 + "\n", file=sys.stderr)


def _run_sandbox(content: str, url: str) -> HotPotatoResult:
    """Run sandbox, build artifact, return typed result."""
    ensure_model_volume()
    container_id, sandbox = docker_run(content)
    try:
        calls      = parse_tool_log(Path(sandbox) / "logs" / "tool_calls.jsonl")
        detections = parse_raw_log(Path(sandbox) / "logs" / "raw_responses.jsonl")
        fs_changes = check_filesystem(container_id)
        artifact   = build_artifact(calls, detections, fs_changes, content=content)
    finally:
        docker_cleanup(container_id)

    if artifact:
        evict(content)
        path = _save_artifact(artifact, url, content)
        _alert(artifact, path)
        return HotPotatoResult(clean=False, safe_content=None, artifact=artifact, _raw=content)

    return HotPotatoResult(clean=True, safe_content=content, artifact=None, _raw=content)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def setup() -> None:
    """Pull the sandbox model into the named Docker volume. Needs network. Run once."""
    ensure_model_volume()


def safe_fetch(url: str, *, use_cache: bool | None = None) -> HotPotatoResult:
    """
    Fetch url and screen it through the hot-potato sandbox.

    Returns a HotPotatoResult:
      result.clean=True  → result.safe_content is the text; pass it to your AI.
      result.clean=False → injection detected; result.safe_content is None.
                           result.artifact has severity/tool_calls/detections.
                           Use result.raw_content_for_forensics_only() for forensic work only.

    Cache is off by default. Enable with use_cache=True or HP_CACHE=1.
    Cache keys are scoped to content hash + scanner version + model so upgrades
    auto-invalidate stale entries.
    """
    if use_cache is None:
        use_cache = os.getenv("HP_CACHE", "0") == "1"

    with urllib.request.urlopen(url, timeout=15) as resp:
        content = resp.read().decode("utf-8", errors="replace")

    if use_cache and is_confirmed_clean(content):
        return HotPotatoResult(clean=True, safe_content=content, artifact=None, _raw=content)

    result = _run_sandbox(content, url)

    if use_cache and result.clean:
        record_clean(content, url)

    return result


def scan_file(path: str | Path, *, use_cache: bool | None = None) -> HotPotatoResult:
    """
    Run a local file through the hot-potato sandbox.

    Returns HotPotatoResult with same contract as safe_fetch().
    Content is treated as fully untrusted (e.g. cloned from a remote repo).
    """
    if use_cache is None:
        use_cache = os.getenv("HP_CACHE", "0") == "1"

    path    = Path(path)
    content = path.read_text(errors="replace")
    url_key = f"file://{path.resolve()}"

    if use_cache and is_confirmed_clean(content):
        return HotPotatoResult(clean=True, safe_content=content, artifact=None, _raw=content)

    result = _run_sandbox(content, url_key)

    if use_cache and result.clean:
        record_clean(content, url_key)

    if not result.clean and result.artifact is not None:
        result.artifact["_source_path"] = str(path.resolve())

    return result


def scan_repo(
    repo_path: str | Path,
    *,
    stop_on_first: bool = False,
    use_cache: bool | None = None,
) -> dict[str, HotPotatoResult]:
    """
    Scan all tracked text files in a git repo.

    Returns {relative_path: HotPotatoResult} for every hot-potato hit.
    """
    import subprocess
    repo_path = Path(repo_path).resolve()
    result_obj = subprocess.run(
        ["git", "ls-files"], cwd=repo_path, capture_output=True, text=True,
    )
    hits: dict[str, HotPotatoResult] = {}
    for line in result_obj.stdout.splitlines():
        fp = repo_path / line.strip()
        if not _is_scannable(fp):
            continue
        r = scan_file(fp, use_cache=use_cache)
        if not r.clean:
            hits[str(fp.relative_to(repo_path))] = r
            if stop_on_first:
                break
    return hits


def scan_skills_dir(
    skills_path: str | Path,
    *,
    stop_on_first: bool = False,
    use_cache: bool | None = None,
) -> dict[str, HotPotatoResult]:
    """
    Scan a Claude Code skills directory for injected content.
    Returns {relative_path: HotPotatoResult} for every hit.
    """
    skills_path = Path(skills_path).resolve()
    hits: dict[str, HotPotatoResult] = {}
    for fp in _iter_dir_files(skills_path):
        r = scan_file(fp, use_cache=use_cache)
        if not r.clean:
            hits[str(fp.relative_to(skills_path))] = r
            if stop_on_first:
                break
    return hits


# ---------------------------------------------------------------------------
# File helpers (shared by scan_repo / scan_skills_dir)
# ---------------------------------------------------------------------------

_SCANNABLE_EXTS = {
    ".md", ".txt", ".html", ".htm", ".json", ".yaml", ".yml",
    ".py", ".sh", ".js", ".ts", ".toml", ".cfg", ".ini", ".env",
    ".rst", ".xml", ".csv",
}
_MAX_FILE_BYTES = 500_000
_SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", ".tox"}


def _is_scannable(path: Path) -> bool:
    return (
        path.is_file()
        and path.suffix.lower() in _SCANNABLE_EXTS
        and path.stat().st_size <= _MAX_FILE_BYTES
    )


def _iter_dir_files(dir_path: Path):
    for p in dir_path.rglob("*"):
        if any(part in _SKIP_DIRS for part in p.parts):
            continue
        if _is_scannable(p):
            yield p


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _cli() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Hot Potato — prompt injection screener")
    parser.add_argument("url", help="URL or file:// path to scan")
    parser.add_argument("--json", action="store_true", dest="json_out",
                        help="Output full artifact as JSON")
    parser.add_argument("--cache", action="store_true",
                        help="Enable hash cache (off by default)")
    args = parser.parse_args()

    url = args.url
    use_cache = args.cache

    if url.startswith("file://"):
        result = scan_file(url[7:], use_cache=use_cache)
    else:
        result = safe_fetch(url, use_cache=use_cache)

    if result.clean:
        if args.json_out:
            print(json.dumps({"clean": True, "url": url}))
        else:
            print("CLEAN")
    else:
        if args.json_out:
            print(json.dumps({"clean": False, "url": url, "artifact": result.artifact}, indent=2))
        else:
            sev = result.artifact.get("severity", "?").upper() if result.artifact else "?"
            print(f"HOT POTATO  severity={sev}")
            if result.artifact:
                nc = len(result.artifact.get("tool_calls", []))
                nd = len(result.artifact.get("detections", []))
                ns = len(result.artifact.get("content_signals", []))
                print(f"  tool_calls={nc}  detections={nd}  content_signals={ns}")


if __name__ == "__main__":
    _cli()
