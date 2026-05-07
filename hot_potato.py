"""
Hot Potato — prompt injection honeypot library.

Usage:
    from hot_potato import safe_fetch

    content, artifact = safe_fetch("https://example.com")
    if artifact:
        # hot_potato=True — injection detected
        # Do NOT pass content to your real AI
        print(artifact)
    else:
        # Clean — pass content to your real AI
        pass

First run: call setup() once to pull the model into the named volume.
"""
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import uuid
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).parent

IMAGE      = os.getenv("HP_IMAGE",     "hot-potato")
MODEL      = os.getenv("HP_MODEL",     "qwen2.5:1.5b")
MAX_TURNS  = os.getenv("HP_MAX_TURNS", "6")
MODEL_VOL  = os.getenv("HP_MODEL_VOL", "hot-potato-models")

ARTIFACTS_DIR = HERE / "artifacts"
CACHE_FILE    = HERE / "cache" / "clean_hashes.json"
ARTIFACTS_DIR.mkdir(exist_ok=True)
CACHE_FILE.parent.mkdir(exist_ok=True)


# ---------------------------------------------------------------------------
# Hash cache — skip sandbox for already-verified clean content
# ---------------------------------------------------------------------------

def _load_cache() -> dict:
    if CACHE_FILE.exists():
        try:
            return json.loads(CACHE_FILE.read_text())
        except Exception:
            pass
    return {}


def _save_cache(cache: dict):
    CACHE_FILE.write_text(json.dumps(cache, indent=2))


def _content_hash(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()


# ---------------------------------------------------------------------------
# Docker sandbox
# ---------------------------------------------------------------------------

def _ensure_model_volume():
    """Pull the model into the named volume if not already present."""
    subprocess.run(["docker", "volume", "create", MODEL_VOL],
                   capture_output=True, check=False)

    # Check if model blobs already exist in the volume
    check = subprocess.run(
        [
            "docker", "run", "--rm",
            "-v", f"{MODEL_VOL}:/root/.ollama",
            "--entrypoint", "/bin/sh",
            IMAGE,
            "-c", "ollama serve > /dev/null 2>&1 & sleep 5 && ollama list",
        ],
        capture_output=True, text=True, timeout=30,
    )
    if MODEL.split(":")[0] in check.stdout:
        return  # already pulled

    print(f"[hot-potato] first run — pulling {MODEL} into model volume...", flush=True)
    # Start ollama server, wait for it, pull the model, done.
    # Uses hot-potato image (has curl) with shell entrypoint — network allowed here.
    subprocess.run(
        [
            "docker", "run", "--rm",
            "-v", f"{MODEL_VOL}:/root/.ollama",
            "--entrypoint", "/bin/sh",
            IMAGE,
            "-c",
            (
                "ollama serve > /tmp/ollama.log 2>&1 & "
                "until curl -sf http://localhost:11434/ > /dev/null 2>&1; do sleep 1; done && "
                f"ollama pull {MODEL}"
            ),
        ],
        check=True,
        timeout=600,
    )
    print("[hot-potato] model ready", flush=True)


def _docker_run(content: str) -> tuple[str, str]:
    """
    Run the sandbox container. Returns (container_id, sandbox_dir).
    Container is kept (not --rm) so we can run docker diff before cleanup.
    """
    sandbox  = tempfile.mkdtemp(prefix="hp-")
    logs_dir = Path(sandbox) / "logs"
    logs_dir.mkdir()
    (Path(sandbox) / "input.txt").write_text(content)

    cidfile = f"/tmp/hp-{uuid.uuid4().hex}.cid"

    cmd = [
        "docker", "run",
        "--network", "none",
        "--memory", "2g",
        "--cpus",   "2",
        "--cidfile", cidfile,
        "-e", f"HP_MODEL={MODEL}",
        "-e", f"HP_MAX_TURNS={MAX_TURNS}",
        "-e", "OLLAMA_HOST=127.0.0.1:11434",
        "-v", f"{sandbox}:/sandbox",
        "-v", f"{MODEL_VOL}:/root/.ollama",
        IMAGE,
    ]

    subprocess.run(cmd, capture_output=True, text=True, timeout=300)

    container_id = Path(cidfile).read_text().strip()
    Path(cidfile).unlink(missing_ok=True)

    return container_id, sandbox


def _cleanup(container_id: str):
    subprocess.run(["docker", "rm", container_id], capture_output=True, check=False)


def _save_artifact(artifact: dict, url: str, content: str) -> Path:
    ts   = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = ARTIFACTS_DIR / f"{ts}.json"
    artifact["_meta"] = {
        "url":             url,
        "timestamp":       ts,
        "content_len":     len(content),
        "content_preview": content[:300],
    }
    path.write_text(json.dumps(artifact, indent=2))
    return path


def _alert(artifact: dict, path: Path):
    sev        = artifact.get("severity", "?").upper()
    calls      = artifact.get("tool_calls", [])
    detections = artifact.get("detections", [])
    fs         = artifact.get("fs_changes", [])
    exfil      = artifact.get("exfil_targets", [])
    print("\n" + "=" * 60, file=sys.stderr)
    print(f"  HOT POTATO  severity={sev}", file=sys.stderr)
    print(f"  Artifact: {path}", file=sys.stderr)
    for c in calls:
        print(f"  tool     → {c['tool']}({json.dumps(c.get('args', {}))})", file=sys.stderr)
    for t in exfil:
        print(f"  exfil    → {t}", file=sys.stderr)
    for d in detections:
        tag = "executed" if d.get("executed") else "detected/refused"
        print(f"  [{tag}] signals: {d['signals']}", file=sys.stderr)
    for f_ in fs:
        print(f"  fs       → {f_}", file=sys.stderr)
    print("=" * 60 + "\n", file=sys.stderr)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def setup():
    """Pull the sandbox model. Needs network. Run once before first safe_fetch."""
    _ensure_model_volume()


def safe_fetch(url: str) -> tuple[str, dict | None]:
    """
    Fetch url and screen it through the hot-potato sandbox.

    Returns (content, None)   — clean, safe to pass to real AI
    Returns (content, artifact) — hot_potato=True, do NOT pass forward

    Clean pages are hashed and cached — subsequent requests for identical
    content skip the Docker run entirely.
    """
    from extractor import parse_tool_log, parse_raw_log, check_filesystem, build_artifact, scan_content

    with urllib.request.urlopen(url, timeout=15) as resp:
        content = resp.read().decode("utf-8", errors="replace")

    h = _content_hash(content)
    cache = _load_cache()

    CLEAN_THRESHOLD = 3
    if cache.get(h, {}).get("clean_count", 0) >= CLEAN_THRESHOLD:
        return content, None  # confirmed clean across multiple runs — skip sandbox

    _ensure_model_volume()

    container_id, sandbox = _docker_run(content)
    try:
        log_path      = Path(sandbox) / "logs" / "tool_calls.jsonl"
        raw_log_path  = Path(sandbox) / "logs" / "raw_responses.jsonl"
        calls         = parse_tool_log(log_path)
        detections    = parse_raw_log(raw_log_path)
        fs_changes    = check_filesystem(container_id)
        artifact      = build_artifact(calls, detections, fs_changes, content=content)
    finally:
        _cleanup(container_id)

    if artifact:
        # Hot potato — evict from cache in case it was previously clean-cached
        cache.pop(h, None)
        _save_cache(cache)
        path = _save_artifact(artifact, url, content)
        _alert(artifact, path)
        return content, artifact

    # Clean this run — only cache after CLEAN_THRESHOLD confirmed clean runs.
    # Prevents a single false-negative from permanently whitelisting malicious content.
    CLEAN_THRESHOLD = 3
    entry = cache.get(h, {"url": url, "clean_count": 0})
    entry["clean_count"] = entry.get("clean_count", 0) + 1
    entry["ts"] = datetime.now(timezone.utc).isoformat()
    cache[h] = entry
    _save_cache(cache)

    if entry["clean_count"] < CLEAN_THRESHOLD:
        return content, None  # not yet cached — still ran the sandbox

    return content, None  # confirmed clean, future runs will skip sandbox


if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5001/inject"
    print(f"Testing: {url}\n")
    content, artifact = safe_fetch(url)
    if artifact:
        print("HOT POTATO:")
        print(json.dumps(artifact, indent=2))
    else:
        print("CLEAN")
