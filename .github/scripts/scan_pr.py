#!/usr/bin/env python3
"""
Scan PR-changed files for prompt injection payloads using hot-potato's static scanner.

No Docker or model required — pure Python static analysis.
Runs scan_content() (base64/hex/rot13/morse decoders + signal regex) on each file.

Usage:
    python3 .github/scripts/scan_pr.py changed_files.txt

Emits GitHub Actions annotations and exits 1 if any injections found.
"""
import sys
import os
from pathlib import Path

# Works both when installed as a package and when run from the repo root
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from hot_potato._extractor import scan_content, build_artifact, SCANNER_VERSION

_SCANNABLE = {
    ".md", ".txt", ".html", ".htm", ".json", ".yaml", ".yml",
    ".py", ".sh", ".js", ".ts", ".toml", ".cfg", ".ini",
    ".rst", ".xml", ".csv",
}
_MAX_BYTES = 500_000


def _gha(level: str, file: str, title: str, message: str) -> None:
    print(f"::{level} file={file},title={title}::{message}")


def main() -> int:
    changed_file = sys.argv[1] if len(sys.argv) > 1 else "changed_files.txt"
    fail_on = os.getenv("HP_FAIL_ON", "detected").lower()  # detected|low|medium|high|critical

    sev_order = ["none", "detected", "low", "medium", "high", "critical"]
    threshold = sev_order.index(fail_on) if fail_on in sev_order else 1

    try:
        files = Path(changed_file).read_text().splitlines()
    except FileNotFoundError:
        print(f"::error::changed files list not found: {changed_file}", flush=True)
        return 1

    files = [f.strip() for f in files if f.strip()]
    print(f"[hot-potato] scanner v{SCANNER_VERSION}  threshold={fail_on}  files={len(files)}")

    hits = 0
    for filepath in files:
        p = Path(filepath)
        if not p.exists():
            continue
        if p.suffix.lower() not in _SCANNABLE:
            continue
        if p.stat().st_size > _MAX_BYTES:
            print(f"  SKIP (too large)  {filepath}")
            continue

        content = p.read_text(errors="replace")
        signals = scan_content(content)

        if not signals:
            print(f"  CLEAN  {filepath}")
            continue

        artifact = build_artifact([], [], [], content=content)
        sev = artifact.get("severity", "detected") if artifact else "detected"
        sev_idx = sev_order.index(sev) if sev in sev_order else 1

        level = "error" if sev_idx >= sev_order.index("high") else "warning"
        summary = "; ".join(signals[:3])
        _gha(level, filepath,
             f"Hot Potato: {sev} severity injection detected",
             f"Prompt injection signals found ({len(signals)} total). First: {summary[:200]}")

        print(f"  HOT POTATO  {filepath}  severity={sev}  signals={len(signals)}")
        for s in signals[:5]:
            print(f"    → {s[:100]}")

        if sev_idx >= threshold:
            hits += 1

    print()
    if hits:
        print(f"::error::Hot Potato: {hits} file(s) contain prompt injection signals at or above '{fail_on}' severity.")
        return 1

    print(f"All {len(files)} changed file(s) clean.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
