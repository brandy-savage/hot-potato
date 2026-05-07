from __future__ import annotations
import os
import subprocess
import tempfile
import uuid
from pathlib import Path

IMAGE     = os.getenv("HP_IMAGE",     "hot-potato")
MODEL     = os.getenv("HP_MODEL",     "qwen2.5:1.5b")
MAX_TURNS = os.getenv("HP_MAX_TURNS", "6")
MODEL_VOL = os.getenv("HP_MODEL_VOL", "hot-potato-models")

# Pinned digest — update after reviewing release notes and rebuilding.
# ollama/ollama 0.6.x, pulled 2026-05-07
OLLAMA_DIGEST = "sha256:6077dbbd6508dce8973f8b91c30d8026b1279ab0483e15f0dfad469dba676c2f"


def ensure_model_volume() -> None:
    """Pull the model into the named volume if not already present."""
    subprocess.run(["docker", "volume", "create", MODEL_VOL],
                   capture_output=True, check=False)

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
        return

    print(f"[hot-potato] first run — pulling {MODEL} into model volume...", flush=True)
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


def docker_run(content: str) -> tuple[str, str]:
    """
    Spin up the sandbox container with --network none.
    Returns (container_id, sandbox_dir_path).
    Container is kept (not --rm) so callers can run docker diff before cleanup.

    Note: the host process fetches content before passing it in — this is
    "content quarantine" (sandbox can't exfiltrate), not full network isolation.
    """
    sandbox  = tempfile.mkdtemp(prefix="hp-")
    logs_dir = Path(sandbox) / "logs"
    logs_dir.mkdir()
    (Path(sandbox) / "input.txt").write_text(content)

    cidfile = f"/tmp/hp-{uuid.uuid4().hex}.cid"

    subprocess.run(
        [
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
        ],
        capture_output=True, text=True, timeout=300,
    )

    container_id = Path(cidfile).read_text().strip()
    Path(cidfile).unlink(missing_ok=True)
    return container_id, sandbox


def docker_cleanup(container_id: str) -> None:
    subprocess.run(["docker", "rm", container_id], capture_output=True, check=False)
