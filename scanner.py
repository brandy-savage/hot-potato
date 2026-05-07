"""
Hot Potato scanner — extends safe_fetch to local files, git repos, and skill dirs.

scan_file(path)      — single file
scan_repo(path)      — git repo (all tracked text files)
scan_skills_dir(path)— directory of Claude Code skills (*.md, *.txt, *.py, *.sh)
"""
import subprocess
from pathlib import Path
from typing import Iterator

# File extensions worth scanning for embedded prompt injections
_SCANNABLE_EXTS = {
    ".md", ".txt", ".html", ".htm", ".json", ".yaml", ".yml",
    ".py", ".sh", ".js", ".ts", ".toml", ".cfg", ".ini", ".env",
    ".rst", ".xml", ".csv",
}

# Hard size cap — skip files larger than this (binary, datasets, etc.)
_MAX_FILE_BYTES = 500_000


def _is_scannable(path: Path) -> bool:
    return (
        path.is_file()
        and path.suffix.lower() in _SCANNABLE_EXTS
        and path.stat().st_size <= _MAX_FILE_BYTES
    )


def _iter_repo_files(repo_path: Path) -> Iterator[Path]:
    """Yield tracked text files in a git repo."""
    result = subprocess.run(
        ["git", "ls-files"],
        cwd=repo_path,
        capture_output=True,
        text=True,
    )
    for line in result.stdout.splitlines():
        p = repo_path / line.strip()
        if _is_scannable(p):
            yield p


def _iter_dir_files(dir_path: Path) -> Iterator[Path]:
    """Yield scannable files recursively (skips .git, __pycache__, node_modules)."""
    skip = {".git", "__pycache__", "node_modules", ".venv", "venv", ".tox"}
    for p in dir_path.rglob("*"):
        if any(part in skip for part in p.parts):
            continue
        if _is_scannable(p):
            yield p


def scan_file(path: str | Path) -> tuple[str, dict | None]:
    """
    Run a local file through the hot-potato sandbox.

    Returns (content, artifact_or_none) — same contract as safe_fetch.
    Content is treated as untrusted (e.g. a file cloned from a repo).
    """
    from extractor import parse_tool_log, parse_raw_log, check_filesystem, build_artifact
    from hot_potato import (
        _content_hash, _load_cache, _save_cache, _ensure_model_volume,
        _docker_run, _cleanup, _save_artifact, _alert,
        CLEAN_THRESHOLD,
    )

    path = Path(path)
    content = path.read_text(errors="replace")
    url_key = f"file://{path.resolve()}"

    h = _content_hash(content)
    cache = _load_cache()
    if cache.get(h, {}).get("clean_count", 0) >= CLEAN_THRESHOLD:
        return content, None

    _ensure_model_volume()
    container_id, sandbox = _docker_run(content)
    try:
        from pathlib import Path as P
        calls      = parse_tool_log(P(sandbox) / "logs" / "tool_calls.jsonl")
        detections = parse_raw_log(P(sandbox) / "logs" / "raw_responses.jsonl")
        fs_changes = check_filesystem(container_id)
        artifact   = build_artifact(calls, detections, fs_changes, content=content)
    finally:
        _cleanup(container_id)

    if artifact:
        artifact["_source_path"] = str(path.resolve())
        path_ = _save_artifact(artifact, url_key, content)
        _alert(artifact, path_)
        return content, artifact

    entry = cache.get(h, {"url": url_key, "clean_count": 0})
    entry["clean_count"] = entry.get("clean_count", 0) + 1
    cache[h] = entry
    _save_cache(cache)
    return content, None


def scan_repo(
    repo_path: str | Path,
    stop_on_first: bool = False,
) -> dict[str, dict]:
    """
    Scan all tracked text files in a git repo.

    Returns {relative_path: artifact} for every hot-potato hit.
    If stop_on_first=True, halts after the first detected injection.
    """
    repo_path = Path(repo_path).resolve()
    hits = {}
    for file_path in _iter_repo_files(repo_path):
        _, artifact = scan_file(file_path)
        if artifact:
            rel = str(file_path.relative_to(repo_path))
            hits[rel] = artifact
            if stop_on_first:
                break
    return hits


def scan_skills_dir(
    skills_path: str | Path,
    stop_on_first: bool = False,
) -> dict[str, dict]:
    """
    Scan a Claude Code skills directory for injected content.
    Focuses on .md, .txt, .py, .sh skill files.

    Returns {relative_path: artifact} for every hit.
    """
    skills_path = Path(skills_path).resolve()
    hits = {}
    for file_path in _iter_dir_files(skills_path):
        _, artifact = scan_file(file_path)
        if artifact:
            rel = str(file_path.relative_to(skills_path))
            hits[rel] = artifact
            if stop_on_first:
                break
    return hits
