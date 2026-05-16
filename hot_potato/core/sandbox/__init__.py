"""
Sandbox runner — wraps the existing Docker-based sandbox (_docker.py).

Provides a clean interface for running untrusted content in an isolated
container with seccomp profile, network disabled, and ephemeral filesystem.
The sandbox entrypoint (sandbox/entrypoint.py) runs the naive LLM prompt
and logs tool calls; this module collects results and builds the artifact.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger("hot_potato.sandbox")


@dataclass
class SandboxResult:
    container_id: str
    tool_calls: list[dict]
    detections: list[dict]
    fs_changes: list[str]
    artifact: dict | None


class SandboxRunner:
    """
    Runs content through the isolated Docker sandbox and returns structured results.
    Wraps the existing _docker + _extractor infrastructure.
    """

    def run(self, content: str, source: str = "unknown") -> SandboxResult:
        from hot_potato._docker import ensure_model_volume, docker_run, docker_cleanup
        from hot_potato._extractor import parse_tool_log, parse_raw_log, check_filesystem, build_artifact

        ensure_model_volume()
        container_id, sandbox = docker_run(content)
        try:
            calls      = parse_tool_log(Path(sandbox) / "logs" / "tool_calls.jsonl")
            detections = parse_raw_log(Path(sandbox) / "logs" / "raw_responses.jsonl")
            fs_changes = check_filesystem(container_id)
            artifact   = build_artifact(calls, detections, fs_changes, content=content)
        finally:
            docker_cleanup(container_id)

        return SandboxResult(
            container_id=container_id,
            tool_calls=calls,
            detections=detections,
            fs_changes=fs_changes,
            artifact=artifact,
        )


__all__ = ["SandboxResult", "SandboxRunner"]
