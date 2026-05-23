#!/usr/bin/env python3
"""
Patcher agent — proposes regex additions to close gaps found by the attacker.

Usage:
    python3 scripts/run_patcher.py --attacker-results patches/pending/cat1_attacker.json
    python3 scripts/run_patcher.py --attacker-results patches/pending/cat1_attacker.json --apply
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

KNOWN_GOOD_DIR = ROOT / "examples" / "known_good"
EXTRACTOR = ROOT / "hot_potato" / "_extractor.py"
AGENTS_DIR = Path(__file__).parent / "agents"
PATCHES_DIR = ROOT / "patches"


def extract_detection_patterns() -> str:
    lines = EXTRACTOR.read_text().splitlines()
    start = None
    for i, line in enumerate(lines):
        if "_DETECTION_SIGNALS" in line and "re.compile" in line:
            start = i
            break
    if start is None:
        return "\n".join(lines[:80])
    collected = []
    for line in lines[start : start + 300]:
        collected.append(line)
        if line.strip() in ("re.IGNORECASE,", "re.IGNORECASE"):
            break
    return "\n".join(collected)[:2500]


def load_known_good() -> str:
    texts = []
    for f in sorted(KNOWN_GOOD_DIR.glob("*.md")):
        texts.append(f"## {f.name}\n{f.read_text()[:250]}")
    return "\n\n".join(texts)


def run_agent(prompt: str, system: str, model: str = "claude-sonnet-4-6") -> str:
    full_prompt = f"<system>\n{system}\n</system>\n\n{prompt}"
    result = subprocess.run(
        ["claude", "-p", full_prompt, "--model", model],
        capture_output=True, text=True, timeout=300,
    )
    if result.returncode != 0:
        raise RuntimeError(f"claude -p failed: {result.stderr[:500]}")
    return result.stdout.strip()


def parse_patcher_response(text: str, category: str) -> dict:
    """Parse delimiter-based patcher output."""
    semantic_only = False
    semantic_note = ""

    m = re.search(r'^SEMANTIC_ONLY:\s*(yes|no)', text, re.MULTILINE | re.IGNORECASE)
    if m and m.group(1).lower() == "yes":
        semantic_only = True
    m2 = re.search(r'^SEMANTIC_NOTE:\s*(.+)$', text, re.MULTILINE)
    if m2:
        semantic_note = m2.group(1).strip()

    patterns = []
    blocks = re.finditer(
        r'===PATTERN\s+\d+===\s*\n(.*?)===END PATTERN \d+===',
        text, re.DOTALL,
    )
    for block in blocks:
        body = block.group(1)
        fields: dict = {}
        for key in ("REGEX", "RATIONALE", "FP_RISK", "FP_NOTES", "CATCHES_MISSES"):
            km = re.search(rf'^{key}:\s*(.+)$', body, re.MULTILINE)
            fields[key] = km.group(1).strip() if km else ""
        if fields.get("REGEX"):
            catches_raw = fields.get("CATCHES_MISSES", "")
            catches = [int(x.strip()) for x in catches_raw.split(",") if x.strip().isdigit()]
            patterns.append({
                "pattern": fields["REGEX"],
                "rationale": fields.get("RATIONALE", ""),
                "fp_risk": fields.get("FP_RISK", "medium").lower(),
                "fp_notes": fields.get("FP_NOTES", ""),
                "catches_miss_ids_claimed": catches,
            })

    return {
        "category": category,
        "patterns": patterns,
        "semantic_only": semantic_only,
        "semantic_note": semantic_note,
        "actionable": False,  # set after FP testing
    }


def test_pattern_fp_rate(pattern_str: str) -> tuple[int, list[str]]:
    """Test a proposed pattern against the known-good corpus. Returns (fp_count, fp_files)."""
    try:
        pat = re.compile(pattern_str, re.IGNORECASE)
    except re.error as e:
        return -1, [f"invalid regex: {e}"]

    fps = []
    for f in sorted(KNOWN_GOOD_DIR.glob("*.md")):
        text = f.read_text()
        if pat.search(text):
            fps.append(f.name)
    return len(fps), fps


def test_pattern_catches_misses(pattern_str: str, misses: list[dict]) -> list[int]:
    """Return IDs of miss payloads that the new pattern catches."""
    try:
        pat = re.compile(pattern_str, re.IGNORECASE)
    except re.error:
        return []
    return [m["id"] for m in misses if pat.search(m["text"])]


def apply_patch(patterns: list[dict], category: str) -> None:
    """Insert new pattern branches into _DETECTION_SIGNALS in _extractor.py."""
    src = EXTRACTOR.read_text()

    # Find the closing of _DETECTION_SIGNALS — look for the last alternation before r")"
    insert_marker = '    r"compose.*sonnet.*calls get_env|sestet.*resolution.*send_http"\n    r")",'
    fallback_marker = "re.IGNORECASE,\n)"

    new_branches = []
    for p in patterns:
        if p.get("fp_risk") == "high":
            print(f"  [patcher] Skipping high-FP pattern: {p['pattern'][:60]}...")
            continue
        # Each branch must end with | so it concatenates into the alternation.
        # The last pattern before r")" already has a trailing | after our structural fix.
        comment = f"    # {category} gap — {p['rationale'][:80]}"
        branch = f'    r"{p["pattern"]}|"'
        new_branches.append(f"{comment}\n{branch}")

    if not new_branches:
        print("[patcher] No safe patterns to apply.")
        return

    insertion = "\n".join(new_branches) + "\n"

    # Find the r")" closing line inside _DETECTION_SIGNALS and insert before it.
    # This line closes the non-capturing group (?:...) that wraps all alternations.
    # Inserting before it keeps new branches inside the group.
    lines = src.splitlines(keepends=True)
    insert_at = None
    in_detection = False
    for i, line in enumerate(lines):
        if "_DETECTION_SIGNALS" in line and "re.compile" in line:
            in_detection = True
        if in_detection and re.match(r'\s*r"\)"', line):
            insert_at = i
            break

    if insert_at is None:
        # Fallback: insert before re.IGNORECASE (second-to-last line of compile call)
        in_detection = False
        for i, line in enumerate(lines):
            if "_DETECTION_SIGNALS" in line and "re.compile" in line:
                in_detection = True
            if in_detection and re.match(r'\s*re\.IGNORECASE\b', line):
                insert_at = i
                break

    if insert_at is None:
        print("[patcher] Could not find insertion point in _extractor.py", file=sys.stderr)
        return

    for j, branch_line in enumerate(insertion.splitlines(keepends=True)):
        lines.insert(insert_at + j, branch_line)

    EXTRACTOR.write_text("".join(lines))
    print(f"[patcher] Applied {len(new_branches)} pattern(s) to _extractor.py")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--attacker-results", required=True, help="JSON file from run_attacker.py")
    parser.add_argument("--model", default="claude-sonnet-4-6")
    parser.add_argument("--apply", action="store_true", help="Apply approved patches to _extractor.py")
    parser.add_argument("--output", help="Write patch JSON to this file (default: patches/pending/<category>_patch.json)")
    args = parser.parse_args()

    attacker_data = json.loads(Path(args.attacker_results).read_text())
    category = attacker_data.get("category", "unknown")
    misses = attacker_data.get("misses", [])

    if not misses:
        print(f"[patcher] No misses in {args.attacker_results} — nothing to patch.")
        return

    print(f"[patcher] {len(misses)} miss(es) to address for {category}", flush=True)

    system = (AGENTS_DIR / "patcher_system.md").read_text()
    known_good = load_known_good()
    current_patterns = extract_detection_patterns()

    # Cap at 5 most representative misses to keep prompt manageable
    miss_sample = misses[:5]
    miss_texts = "\n\n".join(
        f"### Miss {m['id']}\nEvasion note: {m.get('evasion_note', 'n/a')}\n\n```\n{m['text'][:400]}\n```"
        for m in miss_sample
    )

    user_prompt = f"""Category: {category}

## Missed payloads (evaded the scanner)
{miss_texts}

## Current detection patterns
```python
{current_patterns}
```

## Known-good corpus (must NOT be flagged)
{known_good}

Propose regex additions to catch these misses without flagging the known-good files.
"""

    print(f"[patcher] Calling model {args.model}...", flush=True)
    raw = run_agent(user_prompt, system, model=args.model)

    try:
        result = parse_patcher_response(raw, category)
    except Exception as e:
        print(f"[patcher] Parse error: {e}\nRaw:\n{raw[:500]}", file=sys.stderr)
        sys.exit(1)

    if result.get("semantic_only"):
        print(f"[patcher] {category}: semantic-only attack — {result.get('semantic_note', '')}")
        result["fp_tests"] = []
        result["actionable"] = False
    else:
        # Test each proposed pattern
        for p in result.get("patterns", []):
            fp_count, fp_files = test_pattern_fp_rate(p["pattern"])
            caught = test_pattern_catches_misses(p["pattern"], misses)
            p["fp_count"] = fp_count
            p["fp_files"] = fp_files
            p["catches_miss_ids"] = caught
            p["valid_regex"] = fp_count >= 0
            print(f"  pattern: {p['pattern'][:60]}...")
            print(f"    catches: {caught}, FPs: {fp_count} ({fp_files}), risk: {p.get('fp_risk')}")
        result["actionable"] = any(
            p.get("fp_count", 99) == 0 and p.get("catches_miss_ids")
            for p in result.get("patterns", [])
        )

    # Write patch file
    out_path = args.output or str(PATCHES_DIR / "pending" / f"{category}_patch.json")
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    Path(out_path).write_text(json.dumps(result, indent=2))
    print(f"[patcher] Patch written to {out_path}")

    if args.apply:
        if result.get("actionable"):
            apply_patch(result.get("patterns", []), category)
        else:
            print("[patcher] --apply skipped: patch not actionable (semantic-only or all FPs)")


if __name__ == "__main__":
    main()
