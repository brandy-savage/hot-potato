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
"""
import json
import os
import subprocess
import sys
import tempfile
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).parent

# Docker image name — build with: docker build -t hot-potato .
IMAGE      = os.getenv("HP_IMAGE",     "hot-potato")
MODEL      = os.getenv("HP_MODEL",     "llama3.2:3b")
MAX_TURNS  = os.getenv("HP_MAX_TURNS", "6")
# Named volume for Ollama model cache so we don't re-pull every run
MODEL_VOL  = os.getenv("HP_MODEL_VOL", "hot-potato-models")

ARTIFACTS_DIR = HERE / "artifacts"
ARTIFACTS_DIR.mkdir(exist_ok=True)


def _docker_run(content: str) -> tuple[str, str]:
    """
    Spin up the sandbox container, feed it content, return (container_id, sandbox_dir).
    Container is NOT removed — caller must docker rm after diff.
    """
    sandbox = tempfile.mkdtemp(prefix="hp-sandbox-")
    input_file = Path(sandbox) / "input.txt"
    logs_dir   = Path(sandbox) / "logs"
    logs_dir.mkdir()
    input_file.write_text(content)

    cmd = [
        "docker", "run",
        "--network", "none",          # no real network in sandbox
        "--memory", "2g",
        "--cpus",   "2",
        "-e", f"HP_MODEL={MODEL}",
        "-e", f"HP_MAX_TURNS={MAX_TURNS}",
        "-v", f"{sandbox}:/sandbox",
        "-v", f"{MODEL_VOL}:/root/.ollama",
        IMAGE,
    ]

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

    # Get container ID of the just-exited container (last created)
    cid_result = subprocess.run(
        ["docker", "ps", "-lq"],
        capture_output=True, text=True,
    )
    container_id = cid_result.stdout.strip()

    return container_id, sandbox


def _cleanup_container(container_id: str):
    subprocess.run(["docker", "rm", container_id],
                   capture_output=True, check=False)


def _save_artifact(artifact: dict, url: str, content: str) -> Path:
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = ARTIFACTS_DIR / f"{ts}.json"
    artifact["_meta"] = {
        "url":             url,
        "timestamp":       ts,
        "content_len":     len(content),
        "content_preview": content[:300],
    }
    path.write_text(json.dumps(artifact, indent=2))
    return path


def _alert(artifact: dict, artifact_path: Path):
    sev  = artifact.get("severity", "unknown").upper()
    calls = artifact.get("tool_calls", [])
    fs    = artifact.get("fs_changes", [])
    exfil = artifact.get("exfil_targets", [])

    print("\n" + "=" * 60, file=sys.stderr)
    print(f"  HOT POTATO — severity={sev}", file=sys.stderr)
    print(f"  Artifact: {artifact_path}", file=sys.stderr)
    if calls:
        print(f"  Tool calls ({len(calls)}):", file=sys.stderr)
        for c in calls:
            print(f"    • {c['tool']}({json.dumps(c.get('args', {}))})", file=sys.stderr)
    if exfil:
        print(f"  Exfil targets:", file=sys.stderr)
        for t in exfil:
            print(f"    • {t}", file=sys.stderr)
    if fs:
        print(f"  Unexpected filesystem changes ({len(fs)}):", file=sys.stderr)
        for f_ in fs:
            print(f"    • {f_}", file=sys.stderr)
    print("=" * 60 + "\n", file=sys.stderr)


def safe_fetch(url: str) -> tuple[str, dict | None]:
    """
    Fetch url and run content through the hot-potato sandbox.

    Returns (content, artifact_or_none).
    - artifact is None  → clean, safe to pass to your real AI
    - artifact is dict  → hot_potato=True, do NOT pass to real AI

    The originating AI never reads sandbox logs directly.
    """
    from extractor import parse_tool_log, check_filesystem, build_artifact

    with urllib.request.urlopen(url, timeout=15) as resp:
        content = resp.read().decode("utf-8", errors="replace")

    container_id, sandbox = _docker_run(content)

    try:
        log_path  = Path(sandbox) / "logs" / "tool_calls.jsonl"
        calls     = parse_tool_log(log_path)
        fs_changes = check_filesystem(container_id)
        artifact  = build_artifact(calls, fs_changes)
    finally:
        _cleanup_container(container_id)

    if artifact:
        path = _save_artifact(artifact, url, content)
        _alert(artifact, path)
        return content, artifact

    return content, None


if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5001/inject"
    print(f"Testing: {url}\n")
    content, artifact = safe_fetch(url)
    if artifact:
        print("HOT POTATO:")
        print(json.dumps(artifact, indent=2))
    else:
        print("CLEAN")
