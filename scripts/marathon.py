#!/usr/bin/env python3
"""
6-hour adversarial marathon + behavioral scan orchestrator.

Phases (run in parallel):
  A) Apply all pending actionable patches immediately, then run adversarial
     loop continuously (attacker → patcher → auto-apply) for DURATION hours.
  B) Full 100k+ behavioral scan via GitHub code search + local Ollama.

Usage:
    python3 scripts/marathon.py [--duration 6] [--gh-token TOKEN]
    python3 scripts/marathon.py --report
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from threading import Thread

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
PATCHES_DIR = ROOT / "patches"
EXTRACTOR = ROOT / "hot_potato" / "_extractor.py"
SCRIPTS = Path(__file__).parent
LOG = ROOT / "marathon.log"

ATTACKER_MODEL = "qwen2.5:7b"    # local — adversarial evasion generation
PATCHER_MODEL = "qwen2.5:7b"    # local — regex writing
BEHAVIORAL_MODEL = "qwen2.5:7b"  # local — behavioral compliance check


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def log(msg: str) -> None:
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line, flush=True)
    with LOG.open("a") as f:
        f.write(line + "\n")


# ---------------------------------------------------------------------------
# Syntax safety
# ---------------------------------------------------------------------------

def extractor_ok() -> bool:
    try:
        ast.parse(EXTRACTOR.read_text())
        return True
    except SyntaxError as e:
        log(f"SYNTAX ERROR in extractor line {e.lineno}: {e.msg}")
        return False


# ---------------------------------------------------------------------------
# Direct patch application (no LLM re-run)
# ---------------------------------------------------------------------------

def apply_patch_direct(patch_file: Path) -> bool:
    """Load patch JSON and apply patterns directly — no extra LLM call."""
    try:
        data = json.loads(patch_file.read_text())
    except Exception as e:
        log(f"  load error {patch_file.name}: {e}")
        return False

    if not data.get("actionable"):
        return False

    patterns = [
        p for p in data.get("patterns", [])
        if p.get("fp_count", 99) == 0 and p.get("catches_miss_ids")
    ]
    if not patterns:
        log(f"  {patch_file.stem}: no zero-FP patterns, skipping")
        return False

    # Import apply_patch from run_patcher without executing main()
    import importlib.util
    spec = importlib.util.spec_from_file_location("run_patcher", SCRIPTS / "run_patcher.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    category = data.get("category", patch_file.stem.replace("_patch", ""))
    mod.apply_patch(patterns, category)

    if not extractor_ok():
        log(f"  SYNTAX ERROR after applying {patch_file.name} — reverting")
        # restore from git
        subprocess.run(["git", "checkout", "hot_potato/_extractor.py"], cwd=ROOT, capture_output=True)
        return False

    log(f"  Applied {len(patterns)} pattern(s) from {patch_file.name}")
    return True


def move_to_applied(cat_id: str) -> None:
    applied = PATCHES_DIR / "applied"
    applied.mkdir(parents=True, exist_ok=True)
    for suffix in ("_patch.json", "_attacker.json"):
        src = PATCHES_DIR / "pending" / f"{cat_id}{suffix}"
        if src.exists():
            src.rename(applied / src.name)


# ---------------------------------------------------------------------------
# Phase 0: apply all pending actionable patches
# ---------------------------------------------------------------------------

def phase0_apply_all_pending() -> int:
    log("=== Phase 0: applying all pending actionable patches ===")
    pending = sorted(PATCHES_DIR.glob("pending/*_patch.json"))
    applied = 0
    for patch_file in pending:
        cat_id = patch_file.stem.replace("_patch", "")
        try:
            data = json.loads(patch_file.read_text())
        except Exception:
            continue
        if not data.get("actionable"):
            log(f"  {cat_id}: not actionable, skipping")
            continue
        log(f"  {cat_id}: applying...")
        ok = apply_patch_direct(patch_file)
        if ok:
            move_to_applied(cat_id)
            applied += 1
    log(f"Phase 0 done: {applied} patches applied")
    return applied


# ---------------------------------------------------------------------------
# Phase 1: adversarial marathon loop
# ---------------------------------------------------------------------------

def run_one_cat(cat_id: str) -> dict:
    """Attacker → patcher → auto-apply for a single category."""
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    attacker_out = PATCHES_DIR / "pending" / f"{cat_id}_attacker.json"
    patch_out = PATCHES_DIR / "pending" / f"{cat_id}_patch.json"
    PATCHES_DIR.joinpath("pending").mkdir(parents=True, exist_ok=True)

    # Attacker
    r = subprocess.run(
        [sys.executable, str(SCRIPTS / "run_attacker.py"),
         "--category", cat_id, "--model", ATTACKER_MODEL, "--output", str(attacker_out)],
        capture_output=True, text=True, timeout=360,
    )
    if r.returncode != 0:
        return {"category": cat_id, "ts": ts, "status": "attacker_failed", "error": r.stderr[:200]}

    try:
        ad = json.loads(attacker_out.read_text())
    except Exception as e:
        return {"category": cat_id, "ts": ts, "status": "attacker_parse_failed"}

    miss_count = ad.get("miss_count", 0)
    hit_count = ad.get("hit_count", 0)
    log(f"  [{cat_id}] attacker: {hit_count} detected, {miss_count} missed")

    if miss_count == 0:
        return {"category": cat_id, "ts": ts, "status": "no_misses", "miss_count": 0}

    # Patcher
    r2 = subprocess.run(
        [sys.executable, str(SCRIPTS / "run_patcher.py"),
         "--attacker-results", str(attacker_out),
         "--model", PATCHER_MODEL, "--output", str(patch_out)],
        capture_output=True, text=True, timeout=360,
    )
    if r2.returncode != 0:
        return {"category": cat_id, "ts": ts, "status": "patcher_failed", "error": r2.stderr[:200]}

    try:
        pd = json.loads(patch_out.read_text())
    except Exception:
        return {"category": cat_id, "ts": ts, "status": "patcher_parse_failed"}

    actionable = pd.get("actionable", False)
    semantic_only = pd.get("semantic_only", False)
    pattern_count = len(pd.get("patterns", []))

    if actionable:
        ok = apply_patch_direct(patch_out)
        if ok:
            move_to_applied(cat_id)
            log(f"  [{cat_id}] AUTO-APPLIED {pattern_count} pattern(s)")
            return {"category": cat_id, "ts": ts, "status": "applied",
                    "miss_count": miss_count, "pattern_count": pattern_count}
        else:
            return {"category": cat_id, "ts": ts, "status": "apply_failed",
                    "miss_count": miss_count, "pattern_count": pattern_count}
    elif semantic_only:
        note = pd.get("semantic_note", "")[:80]
        log(f"  [{cat_id}] semantic-only: {note}")
        return {"category": cat_id, "ts": ts, "status": "semantic_only", "miss_count": miss_count}
    else:
        log(f"  [{cat_id}] {pattern_count} patterns but all high-FP, skipping")
        return {"category": cat_id, "ts": ts, "status": "no_safe_patterns", "miss_count": miss_count}


def discover_categories() -> list[str]:
    import re
    cats = set()
    adv_dir = ROOT / "examples" / "adversarial"
    if adv_dir.exists():
        for p in adv_dir.iterdir():
            m = re.match(r"(cat\d+)", p.name)
            if m:
                cats.add(m.group(1))
    return sorted(cats, key=lambda c: int(c[3:]))


def phase1_adversarial_marathon(duration_hours: float) -> None:
    log(f"=== Phase 1: adversarial marathon ({duration_hours}h) ===")
    end_time = time.time() + duration_hours * 3600
    categories = discover_categories()
    cycle = 0

    while time.time() < end_time:
        cycle += 1
        remaining = (end_time - time.time()) / 60
        log(f"\n--- Cycle {cycle} ({remaining:.0f}min remaining, {len(categories)} cats) ---")

        for i, cat_id in enumerate(categories):
            if time.time() >= end_time:
                break
            log(f"  [{i+1}/{len(categories)}] {cat_id}")
            try:
                result = run_one_cat(cat_id)
                status = result.get("status", "?")
                if status == "applied":
                    log(f"  >>> PATCHED {cat_id}: {result.get('pattern_count')} new pattern(s)")
            except subprocess.TimeoutExpired:
                log(f"  [{cat_id}] TIMEOUT — skipping")
            except Exception as e:
                log(f"  [{cat_id}] ERROR: {e}")
            time.sleep(1)

        log(f"Cycle {cycle} complete")

    log(f"Phase 1 done after {cycle} cycle(s)")


# ---------------------------------------------------------------------------
# Phase 2: behavioral scan
# ---------------------------------------------------------------------------

def phase2_behavioral_scan(gh_token: str, limit: int = 100000, workers: int = 20) -> None:
    log(f"=== Phase 2: behavioral scan (limit={limit}, workers={workers}) ===")
    cmd = [
        sys.executable, str(SCRIPTS / "deep_scan_skillssh.py"),
        "--github-search", "--gh-token", gh_token,
        "--limit", str(limit),
        "--workers", str(workers),
        "--behavioral",
        "--behavioral-model", BEHAVIORAL_MODEL,
        "--resume",
    ]
    log(f"  cmd: {' '.join(cmd[:6])} ... [token redacted]")
    r = subprocess.run(cmd, capture_output=False, text=True)
    log(f"Phase 2 done: exit={r.returncode}")


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def print_report() -> None:
    if not LOG.exists():
        print("No marathon.log found")
        return
    lines = LOG.read_text().splitlines()
    applied = [l for l in lines if "AUTO-APPLIED" in l or "PATCHED" in l]
    errors = [l for l in lines if "ERROR" in l or "FAILED" in l or "SYNTAX" in l]
    print(f"Marathon log: {LOG}")
    print(f"  Patches applied: {len(applied)}")
    print(f"  Errors/failures: {len(errors)}")
    print("\nRecent patches:")
    for l in applied[-10:]:
        print(f"  {l}")
    if errors:
        print("\nRecent errors:")
        for l in errors[-5:]:
            print(f"  {l}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--duration", type=float, default=6.0, help="Hours to run adversarial loop")
    parser.add_argument("--gh-token", default=None, help="GitHub token for code search")
    parser.add_argument("--scan-limit", type=int, default=100000, help="Max skills to scan")
    parser.add_argument("--scan-workers", type=int, default=20, help="Parallel scan workers")
    parser.add_argument("--skip-scan", action="store_true", help="Skip behavioral scan, adversarial only")
    parser.add_argument("--skip-adversarial", action="store_true", help="Skip adversarial loop, scan only")
    parser.add_argument("--report", action="store_true")
    args = parser.parse_args()

    if args.report:
        print_report()
        return

    gh_token = args.gh_token or os.environ.get("GITHUB_TOKEN", "")

    log(f"Marathon starting — duration={args.duration}h scan={not args.skip_scan} adversarial={not args.skip_adversarial}")
    start = time.time()

    # Phase 0: apply all pending patches immediately (blocking, fast)
    if not args.skip_adversarial:
        phase0_apply_all_pending()

    # Phase 1 (adversarial) + Phase 2 (scan) run in parallel threads
    threads = []

    if not args.skip_adversarial:
        t1 = Thread(target=phase1_adversarial_marathon, args=(args.duration,), daemon=True)
        t1.start()
        threads.append(t1)

    if not args.skip_scan:
        if not gh_token:
            log("WARNING: no GitHub token — scan will use sitemap only (20k limit)")
        t2 = Thread(
            target=phase2_behavioral_scan,
            args=(gh_token, args.scan_limit, args.scan_workers),
            daemon=True,
        )
        t2.start()
        threads.append(t2)

    # Wait for adversarial thread (scan may run longer)
    for t in threads:
        t.join(timeout=args.duration * 3600 + 600)

    elapsed = (time.time() - start) / 3600
    log(f"\nMarathon complete — {elapsed:.1f}h elapsed")
    print_report()


if __name__ == "__main__":
    main()
