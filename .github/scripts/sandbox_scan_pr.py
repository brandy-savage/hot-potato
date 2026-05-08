#!/usr/bin/env python3
"""
Full sandbox scan — runs a single file through the Docker+Ollama honeypot.

Called by the GHA matrix job, one process per changed file.
Requires Docker and the hot-potato image to be built on the runner.

Usage:
    HP_MODEL_VOL=/tmp/hp-model-cache python3 .github/scripts/sandbox_scan_pr.py path/to/file.md

Exits 0 (clean) or 1 (hot potato). Emits GHA annotations.

TODO: K8s parallel runner
  Serial sandbox runs are 2-5 min each. For repos with large PRs, consider:
  - Self-hosted runners on a K8s cluster (one pod per file, GPU nodes optional)
  - A dispatch action that submits files to a hot-potato K8s job queue
  - Shared model PVC (ReadOnlyMany) so every pod skips the pull
  - Result aggregator job collects pod exit codes + artifact JSONs
  Reference architecture sketch: https://github.com/brandy-savage/hot-potato/issues
"""
import json
import sys
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from hot_potato import scan_file
from hot_potato._extractor import SCANNER_VERSION

_SCANNABLE = {
    ".md", ".txt", ".html", ".htm", ".json", ".yaml", ".yml",
    ".py", ".sh", ".js", ".ts", ".toml", ".cfg", ".ini",
    ".rst", ".xml", ".csv",
}
_MAX_BYTES = 500_000


def _gha(level: str, file: str, title: str, message: str) -> None:
    print(f"::{level} file={file},title={title}::{message}", flush=True)


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: sandbox_scan_pr.py <filepath>", file=sys.stderr)
        return 2

    filepath = sys.argv[1]
    p = Path(filepath)

    print(f"[hot-potato] sandbox scan  file={filepath}  scanner={SCANNER_VERSION}", flush=True)

    if not p.exists():
        print(f"  SKIP (not found)  {filepath}")
        return 0
    if p.suffix.lower() not in _SCANNABLE:
        print(f"  SKIP (extension)  {filepath}")
        return 0
    if p.stat().st_size > _MAX_BYTES:
        print(f"  SKIP (too large)  {filepath}")
        return 0

    print(f"  running sandbox...  {filepath}", flush=True)
    result = scan_file(p)

    if result.clean:
        print(f"  CLEAN  {filepath}")
        return 0

    artifact = result.artifact or {}
    sev = artifact.get("severity", "detected")
    calls = artifact.get("tool_calls", [])
    dets = artifact.get("detections", [])
    signals = artifact.get("content_signals", [])
    exfil = artifact.get("exfil_targets", [])

    level = "error" if sev in ("critical", "high") else "warning"
    detail_parts = []
    if calls:
        detail_parts.append(f"tool_calls: {', '.join(c['tool'] for c in calls)}")
    if exfil:
        detail_parts.append(f"exfil: {exfil[0]}")
    if signals:
        detail_parts.append(f"signals: {signals[0][:80]}")
    detail = " | ".join(detail_parts) or "see artifact"

    _gha(level, filepath,
         f"Hot Potato: {sev} — AI executed injection",
         f"Sandbox AI fell for it. {detail}")

    print(f"  HOT POTATO  {filepath}  severity={sev}")
    print(f"    tool_calls={len(calls)}  detections={len(dets)}  content_signals={len(signals)}")
    for c in calls:
        print(f"    tool  → {c['tool']}({json.dumps(c.get('args', {}))})")
    for t in exfil:
        print(f"    exfil → {t}")

    print(json.dumps(artifact, indent=2), flush=True)
    return 1


if __name__ == "__main__":
    sys.exit(main())
