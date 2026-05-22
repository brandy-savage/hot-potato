#!/usr/bin/env python3
"""
Adversarial loop — orchestrates attacker + patcher agents across all categories.

Each cycle:
  1. Attacker generates evasion variants for a category
  2. Scanner tests each variant — misses are surfaced
  3. Patcher proposes minimal regex additions for each miss
  4. FP-safe patches written to patches/pending/
  5. Notification sent (print / Discord) for human review

Human review: inspect patches/pending/<cat>_patch.json, then:
  python3 scripts/adversarial_loop.py --approve cat1

Usage:
  python3 scripts/adversarial_loop.py --all                  # run all 74 categories
  python3 scripts/adversarial_loop.py --category cat6        # single category
  python3 scripts/adversarial_loop.py --resume               # skip already-processed
  python3 scripts/adversarial_loop.py --approve cat1         # apply a pending patch
  python3 scripts/adversarial_loop.py --report               # summary of pending patches
  python3 scripts/adversarial_loop.py --rerun-misses         # only re-run categories with previous misses
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ADVERSARIAL_DIR = ROOT / "examples" / "adversarial"
PATCHES_DIR = ROOT / "patches"
STATE_FILE = ROOT / "patches" / "loop_state.jsonl"
ATTACKER_SCRIPT = Path(__file__).parent / "run_attacker.py"
PATCHER_SCRIPT = Path(__file__).parent / "run_patcher.py"


def discover_categories() -> list[str]:
    """Return sorted list of category IDs from examples/adversarial/."""
    cats = set()
    for p in ADVERSARIAL_DIR.iterdir():
        m = __import__("re").match(r"(cat\d+)", p.name)
        if m:
            cats.add(m.group(1))
    return sorted(cats, key=lambda c: int(c[3:]))


def load_state() -> dict[str, dict]:
    """Load state from JSONL state file. Returns {category: last_state_entry}."""
    state: dict[str, dict] = {}
    if not STATE_FILE.exists():
        return state
    for line in STATE_FILE.read_text().splitlines():
        line = line.strip()
        if line:
            try:
                entry = json.loads(line)
                state[entry["category"]] = entry
            except Exception:
                pass
    return state


def write_state(entry: dict) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with STATE_FILE.open("a") as f:
        f.write(json.dumps(entry) + "\n")


def run_subprocess(cmd: list[str], label: str) -> tuple[int, str, str]:
    print(f"  [{label}] running: {' '.join(cmd)}", flush=True)
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=360)
    return result.returncode, result.stdout, result.stderr


def process_category(cat_id: str, model: str, attacker_model: str, dry_run: bool) -> dict:
    """Run attacker + patcher for one category. Returns state entry."""
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    attacker_out = PATCHES_DIR / "pending" / f"{cat_id}_attacker.json"
    patch_out = PATCHES_DIR / "pending" / f"{cat_id}_patch.json"
    PATCHES_DIR.joinpath("pending").mkdir(parents=True, exist_ok=True)

    # Step 1: Attacker
    rc, stdout, stderr = run_subprocess([
        sys.executable, str(ATTACKER_SCRIPT),
        "--category", cat_id,
        "--model", attacker_model,
        "--output", str(attacker_out),
    ], "attacker")

    if rc != 0:
        print(f"  [attacker] FAILED for {cat_id}: {stderr[:200]}", flush=True)
        return {"category": cat_id, "ts": ts, "status": "attacker_failed", "error": stderr[:200]}

    try:
        attacker_data = json.loads(attacker_out.read_text())
    except Exception as e:
        return {"category": cat_id, "ts": ts, "status": "attacker_parse_failed", "error": str(e)}

    miss_count = attacker_data.get("miss_count", 0)
    hit_count = attacker_data.get("hit_count", 0)
    print(f"  [{cat_id}] attacker: {hit_count} detected, {miss_count} missed", flush=True)

    if miss_count == 0:
        state = {
            "category": cat_id, "ts": ts, "status": "no_misses",
            "miss_count": 0, "hit_count": hit_count,
        }
        write_state(state)
        return state

    # Step 2: Patcher
    rc, stdout, stderr = run_subprocess([
        sys.executable, str(PATCHER_SCRIPT),
        "--attacker-results", str(attacker_out),
        "--model", model,
        "--output", str(patch_out),
    ], "patcher")

    if rc != 0:
        print(f"  [patcher] FAILED for {cat_id}: {stderr[:200]}", flush=True)
        return {"category": cat_id, "ts": ts, "status": "patcher_failed", "error": stderr[:200]}

    try:
        patch_data = json.loads(patch_out.read_text())
    except Exception as e:
        return {"category": cat_id, "ts": ts, "status": "patcher_parse_failed", "error": str(e)}

    actionable = patch_data.get("actionable", False)
    semantic_only = patch_data.get("semantic_only", False)
    pattern_count = len(patch_data.get("patterns", []))

    state = {
        "category": cat_id,
        "ts": ts,
        "status": "patch_ready" if actionable else ("semantic_only" if semantic_only else "no_safe_patterns"),
        "miss_count": miss_count,
        "hit_count": hit_count,
        "pattern_count": pattern_count,
        "actionable": actionable,
        "semantic_only": semantic_only,
        "patch_file": str(patch_out),
    }
    write_state(state)

    if actionable:
        print(f"  [{cat_id}] PATCH READY — {pattern_count} pattern(s) — review: {patch_out}", flush=True)
        _notify_patch_ready(cat_id, miss_count, pattern_count, str(patch_out))
    elif semantic_only:
        print(f"  [{cat_id}] semantic-only miss — no regex can catch it: {patch_data.get('semantic_note', '')[:80]}")
    else:
        print(f"  [{cat_id}] patcher found no safe patterns (all FP risk too high)")

    return state


def _notify_patch_ready(cat_id: str, miss_count: int, pattern_count: int, patch_file: str) -> None:
    """Print a Discord-friendly review notice."""
    print(f"\n{'='*60}", flush=True)
    print(f"PATCH READY: {cat_id}", flush=True)
    print(f"  {miss_count} miss(es) — {pattern_count} proposed pattern(s)", flush=True)
    print(f"  Review: {patch_file}", flush=True)
    print(f"  Approve: python3 scripts/adversarial_loop.py --approve {cat_id}", flush=True)
    print(f"{'='*60}\n", flush=True)


def approve_patch(cat_id: str) -> None:
    """Apply a pending patch to _extractor.py after human review."""
    patch_file = PATCHES_DIR / "pending" / f"{cat_id}_patch.json"
    if not patch_file.exists():
        print(f"No pending patch for {cat_id}")
        return

    rc, stdout, stderr = run_subprocess([
        sys.executable, str(PATCHER_SCRIPT),
        "--attacker-results", str(PATCHES_DIR / "pending" / f"{cat_id}_attacker.json"),
        "--output", str(patch_file),
        "--apply",
    ], "apply")

    if rc != 0:
        print(f"Apply failed: {stderr[:300]}")
        return

    # Move to applied
    applied_dir = PATCHES_DIR / "applied"
    applied_dir.mkdir(parents=True, exist_ok=True)
    patch_file.rename(applied_dir / patch_file.name)
    attacker_file = PATCHES_DIR / "pending" / f"{cat_id}_attacker.json"
    if attacker_file.exists():
        attacker_file.rename(applied_dir / attacker_file.name)

    write_state({
        "category": cat_id,
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "status": "applied",
    })
    print(f"[approve] Patch for {cat_id} applied and moved to patches/applied/")
    print(f"[approve] Run tests to verify: python3 -m pytest tests/")


def print_report() -> None:
    state = load_state()
    categories = discover_categories()

    unprocessed = [c for c in categories if c not in state]
    no_misses = [c for c, s in state.items() if s.get("status") == "no_misses"]
    patch_ready = [c for c, s in state.items() if s.get("status") == "patch_ready"]
    semantic_only = [c for c, s in state.items() if s.get("status") == "semantic_only"]
    applied = [c for c, s in state.items() if s.get("status") == "applied"]
    failed = [c for c, s in state.items() if "failed" in s.get("status", "")]

    print(f"\nAdversarial Loop Report — {datetime.now(timezone.utc).date()}")
    print(f"  Total categories:   {len(categories)}")
    print(f"  Unprocessed:        {len(unprocessed)}")
    print(f"  No misses:          {len(no_misses)}")
    print(f"  Patch ready:        {len(patch_ready)} — {patch_ready}")
    print(f"  Semantic only:      {len(semantic_only)} — {semantic_only}")
    print(f"  Applied:            {len(applied)}")
    print(f"  Failed:             {len(failed)} — {failed}")

    if patch_ready:
        print(f"\nPending approvals:")
        for cat_id in patch_ready:
            s = state[cat_id]
            print(f"  python3 scripts/adversarial_loop.py --approve {cat_id}"
                  f"  # {s.get('miss_count',0)} miss(es), {s.get('pattern_count',0)} pattern(s)")


def main() -> None:
    parser = argparse.ArgumentParser()
    grp = parser.add_mutually_exclusive_group(required=True)
    grp.add_argument("--all", action="store_true", help="Process all categories")
    grp.add_argument("--category", help="Process a single category")
    grp.add_argument("--approve", metavar="CAT_ID", help="Apply a pending patch")
    grp.add_argument("--report", action="store_true", help="Print status report")
    grp.add_argument("--rerun-misses", action="store_true", help="Re-run categories with previous misses")
    parser.add_argument("--resume", action="store_true", help="Skip already-processed categories")
    parser.add_argument("--model", default="claude-sonnet-4-6", help="Patcher model")
    parser.add_argument("--attacker-model", default="claude-opus-4-7", help="Attacker model (more capable = better evasions)")
    parser.add_argument("--dry-run", action="store_true", help="Don't modify _extractor.py")
    parser.add_argument("--delay", type=float, default=2.0, help="Seconds between categories")
    args = parser.parse_args()

    if args.report:
        print_report()
        return

    if args.approve:
        approve_patch(args.approve)
        return

    state = load_state()
    categories = discover_categories()

    if args.category:
        targets = [args.category]
    elif args.rerun_misses:
        targets = [c for c, s in state.items() if s.get("miss_count", 0) > 0]
        print(f"Re-running {len(targets)} categories with previous misses")
    else:
        targets = categories

    if args.resume:
        already_done = {c for c, s in state.items() if s.get("status") in ("no_misses", "patch_ready", "applied", "semantic_only")}
        targets = [t for t in targets if t not in already_done]
        print(f"Resuming: {len(targets)} categories remaining")

    print(f"Processing {len(targets)} categories with attacker={args.attacker_model} patcher={args.model}")

    results = []
    for i, cat_id in enumerate(targets):
        print(f"\n[{i+1}/{len(targets)}] {cat_id}", flush=True)
        result = process_category(cat_id, model=args.model, attacker_model=args.attacker_model, dry_run=args.dry_run)
        results.append(result)
        if i < len(targets) - 1:
            time.sleep(args.delay)

    # Final summary
    misses_found = sum(1 for r in results if r.get("miss_count", 0) > 0)
    patches_ready = sum(1 for r in results if r.get("status") == "patch_ready")
    print(f"\nDone. {len(targets)} categories processed.")
    print(f"  {misses_found} had misses, {patches_ready} patches ready for review.")
    if patches_ready:
        print(f"  Run: python3 scripts/adversarial_loop.py --report")


if __name__ == "__main__":
    main()
