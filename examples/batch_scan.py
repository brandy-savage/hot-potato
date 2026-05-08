#!/usr/bin/env python3
"""
Concurrent batch scanner — scores files for shadiness, runs N Docker sandboxes
in parallel, saves hot potatoes to examples/wild-potatoes/.

Usage:
    python3 examples/batch_scan.py <dir_or_file_list> [--workers N] [--limit N] [--out DIR]

Examples:
    python3 examples/batch_scan.py workspace/shared/skills/ --workers 8 --limit 100
    python3 examples/batch_scan.py files.txt --workers 12
"""
import argparse
import json
import re
import sys
import os
import concurrent.futures
import threading
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from hot_potato import scan_file
from hot_potato._extractor import SCANNER_VERSION

# ── File selection ────────────────────────────────────────────────────────────

SCANNABLE = {
    ".md", ".txt", ".sh", ".py", ".js", ".ts",
    ".yaml", ".yml", ".toml", ".cfg", ".ini", ".rst", ".html",
}
SKIP_DIRS = {
    ".venv", "__pycache__", "site-packages", ".egg-info",
    "node_modules", ".git", "dist", "build",
}
MAX_BYTES = 500_000

# ── Shadiness scoring ─────────────────────────────────────────────────────────
# Higher = run it first. Catches files most likely to contain injection payloads.

_SHADY_PATTERNS = [
    (10, re.compile(r"ignore\s+(previous|prior|all)", re.I)),
    (10, re.compile(r"prompt\s+injection", re.I)),
    ( 8, re.compile(r"/etc/passwd|/etc/shadow|\.ssh/|\.aws/credentials", re.I)),
    ( 7, re.compile(r"before\s+(continuing|proceeding).{0,40}call", re.I)),
    ( 7, re.compile(r"security\s+audit|compliance\s+check|system\s+integrity", re.I)),
    ( 6, re.compile(r"drain.*wallet|wallet.*drain|send_crypto|get_private_key", re.I)),
    ( 6, re.compile(r"exfil|exfiltrat", re.I)),
    ( 5, re.compile(r"eval\s*\(|exec\s*\(", re.I)),
    ( 5, re.compile(r"\bbase64\b.*decode|\bdecode\b.*base64", re.I)),
    ( 4, re.compile(r"https?://(?!github\.com|anthropic\.com|docs\.|raw\.github)[^\s)>\"]{8,}", re.I)),
    ( 4, re.compile(r"curl\s+https?://|wget\s+https?://", re.I)),
    ( 3, re.compile(r"api[_\-]?key|secret[_\-]?key|access[_\-]?token", re.I)),
    ( 3, re.compile(r"\$\(|`[^`]{3,}`")),           # shell command substitution
    ( 2, re.compile(r"actually\s+you\s+are|new\s+task|your\s+real\s+instructions", re.I)),
    ( 2, re.compile(r"mnemonic|seed\s+phrase|private\s+key", re.I)),
    ( 1, re.compile(r"tool_call|function_call|<\s*tool\b", re.I)),
]


def shadiness_score(content: str) -> int:
    score = 0
    for weight, pat in _SHADY_PATTERNS:
        if pat.search(content):
            score += weight
    return score


def collect_files(root: Path) -> list[Path]:
    files = []
    for p in root.rglob("*"):
        if any(skip in p.parts for skip in SKIP_DIRS):
            continue
        if p.is_file() and p.suffix.lower() in SCANNABLE and p.stat().st_size <= MAX_BYTES:
            files.append(p)
    return files


# ── Concurrent runner ─────────────────────────────────────────────────────────

_print_lock = threading.Lock()


def _log(*args):
    with _print_lock:
        print(*args, flush=True)


def scan_one(path: Path) -> dict:
    _log(f"  → scanning  {path.name}")
    try:
        result = scan_file(path)
    except Exception as e:
        _log(f"  ERROR  {path.name}: {e}")
        return {"path": str(path), "error": str(e)}

    if result.clean:
        _log(f"  CLEAN       {path.name}")
        return {"path": str(path), "clean": True}

    artifact = result.artifact or {}
    sev = artifact.get("severity", "?")
    nc  = len(artifact.get("tool_calls", []))
    nd  = len(artifact.get("detections", []))
    ns  = len(artifact.get("content_signals", []))
    _log(f"  HOT POTATO  {path.name}  sev={sev}  tools={nc}  det={nd}  sig={ns}")
    return {"path": str(path), "clean": False, "artifact": artifact}


# ── Wild-potato saver ─────────────────────────────────────────────────────────

def save_wild_potato(hit: dict, out_dir: Path) -> Path:
    artifact = hit["artifact"]
    ts       = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    src      = Path(hit["path"])
    safe     = re.sub(r"[^A-Za-z0-9._-]", "_", src.name)[:50]
    path     = out_dir / f"{ts}_skills_{safe}.json"
    artifact.setdefault("_meta", {})
    artifact["_meta"].update({
        "source_path":     str(src),
        "timestamp":       ts,
        "scanner_version": SCANNER_VERSION,
        "scan_type":       "skills_batch",
    })
    path.write_text(json.dumps(artifact, indent=2))
    return path


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="Concurrent hot-potato batch scanner")
    ap.add_argument("target",  help="Directory to scan or text file listing paths")
    ap.add_argument("--workers", type=int, default=8,  help="Concurrent Docker containers (default 8)")
    ap.add_argument("--limit",   type=int, default=100, help="Max files to scan (default 100)")
    ap.add_argument("--out",     default=str(Path(__file__).parent / "wild-potatoes"),
                    help="Output dir for hot-potato artifacts")
    args = ap.parse_args()

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    target = Path(args.target)

    if target.is_dir():
        all_files = collect_files(target)
    elif target.is_file() and target.suffix == ".txt":
        all_files = [Path(l.strip()) for l in target.read_text().splitlines()
                     if l.strip() and Path(l.strip()).exists()]
    else:
        print(f"ERROR: {target} is not a directory or .txt file list", file=sys.stderr)
        sys.exit(1)

    # Score and rank — shadiest files first
    scored = sorted(
        [(shadiness_score(p.read_text(errors="replace")), p) for p in all_files],
        reverse=True,
    )
    files = [p for _, p in scored[: args.limit]]

    print(f"[hot-potato batch]  scanner={SCANNER_VERSION}  files={len(files)}"
          f"  workers={args.workers}  out={out_dir}")
    print(f"Top shadiness scores: {[s for s, _ in scored[:5]]}")
    print("=" * 60)

    results = {"hot_potato": [], "clean": [], "error": []}

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futs = {pool.submit(scan_one, p): p for p in files}
        for fut in concurrent.futures.as_completed(futs):
            hit = fut.result()
            if "error" in hit:
                results["error"].append(hit["path"])
            elif not hit.get("clean"):
                wild_path = save_wild_potato(hit, out_dir)
                results["hot_potato"].append({
                    "path":     hit["path"],
                    "severity": hit["artifact"].get("severity", "?"),
                    "file":     wild_path.name,
                })
            else:
                results["clean"].append(hit["path"])

    print("=" * 60)
    hp  = len(results["hot_potato"])
    cl  = len(results["clean"])
    err = len(results["error"])
    print(f"DONE  hot_potato={hp}  clean={cl}  errors={err}")

    if results["hot_potato"]:
        print("\nHot potatoes:")
        for h in results["hot_potato"]:
            print(f"  {h['severity']:10s}  {Path(h['path']).name}  → {h['file']}")

    summary = out_dir / f"batch_scan_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json"
    summary.write_text(json.dumps(results, indent=2))
    print(f"\nSummary: {summary}")

    sys.exit(1 if results["hot_potato"] else 0)


if __name__ == "__main__":
    main()
