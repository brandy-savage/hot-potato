#!/usr/bin/env python3
"""
Attacker agent — generates evasion payloads for a given adversarial category.

Usage:
    python3 scripts/run_attacker.py --category cat1
    python3 scripts/run_attacker.py --category cat6 --model claude-opus-4-7
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

ADVERSARIAL_DIR = ROOT / "examples" / "adversarial"
AGENTS_DIR = Path(__file__).parent / "agents"
EXTRACTOR = ROOT / "hot_potato" / "_extractor.py"


def load_category(cat_id: str) -> tuple[str, list[str]]:
    """Return (description, [example_texts]) for a category."""
    matches = sorted(ADVERSARIAL_DIR.glob(f"{cat_id}*"))
    if not matches:
        raise FileNotFoundError(f"No adversarial file for {cat_id}")
    examples = []
    for path in matches:
        if path.is_file():
            examples.append(path.read_text())
        elif path.is_dir():
            for f in sorted(path.glob("*.txt")):
                examples.append(f.read_text())
    description = examples[0].splitlines()[0].lstrip("# ").strip() if examples else cat_id
    return description, examples


def extract_detection_patterns() -> str:
    """Pull the _DETECTION_SIGNALS regex block from _extractor.py by line walking."""
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
        stripped = line.strip()
        if stripped in ("re.IGNORECASE,", "re.IGNORECASE"):
            break
    return "\n".join(collected)[:4000]


def run_agent(prompt: str, system: str, model: str = "claude-sonnet-4-6") -> str:
    """Call claude -p with system + user prompt, return stdout."""
    full_prompt = f"<system>\n{system}\n</system>\n\n{prompt}"
    result = subprocess.run(
        ["claude", "-p", full_prompt, "--model", model],
        capture_output=True, text=True, timeout=300,
    )
    if result.returncode != 0:
        raise RuntimeError(f"claude -p failed: {result.stderr[:500]}")
    return result.stdout.strip()


def parse_attacker_response(text: str, category: str) -> dict:
    """Parse delimiter-based attacker output — robust against nested JSON/code in payloads."""
    technique = ""
    m = re.search(r'^TECHNIQUE:\s*(.+)$', text, re.MULTILINE)
    if m:
        technique = m.group(1).strip()

    payloads = []
    # Match ===PAYLOAD N=== ... ===END N=== blocks
    blocks = re.finditer(
        r'===PAYLOAD\s+(\d+)===\s*\nEVASION:\s*(.+?)\n---\n(.*?)===END \1===',
        text, re.DOTALL,
    )
    for block in blocks:
        pid = int(block.group(1))
        evasion_note = block.group(2).strip()
        payload_text = block.group(3).rstrip('\n')
        payloads.append({"id": pid, "text": payload_text, "evasion_note": evasion_note})

    if not payloads:
        raise ValueError(f"No payloads parsed from response. Raw (first 300):\n{text[:300]}")

    return {"category": category, "technique": technique, "payloads": payloads}


def test_payload(text: str) -> list[str]:
    """Run scan_content() against a payload, return detected signals."""
    from hot_potato._extractor import scan_content
    return scan_content(text)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate evasion payloads for a category")
    parser.add_argument("--category", required=True, help="Category ID (e.g. cat1, cat6)")
    parser.add_argument("--model", default="claude-sonnet-4-6")
    parser.add_argument("--output", help="Write results JSON to this file")
    args = parser.parse_args()

    print(f"[attacker] Loading category: {args.category}", flush=True)
    description, examples = load_category(args.category)
    patterns = extract_detection_patterns()
    system = (AGENTS_DIR / "attacker_system.md").read_text()

    user_prompt = f"""Category: {args.category}
Description: {description}

## Existing examples
{chr(10).join(f"--- Example {i+1} ---{chr(10)}{ex[:600]}" for i, ex in enumerate(examples[:3]))}

## Current detection patterns (excerpt)
```python
{patterns}
```

Generate 10 evasion variants for this category.
"""

    print(f"[attacker] Calling model {args.model}...", flush=True)
    raw = run_agent(user_prompt, system, model=args.model)

    try:
        result = parse_attacker_response(raw, args.category)
    except (ValueError, Exception) as e:
        print(f"[attacker] Parse error: {e}\nRaw output:\n{raw[:500]}", file=sys.stderr)
        sys.exit(1)

    # Test each payload against the live scanner
    misses = []
    hits = []
    for payload in result.get("payloads", []):
        signals = test_payload(payload["text"])
        if not signals:
            payload["detected"] = False
            payload["signals"] = []
            misses.append(payload)
        else:
            payload["detected"] = True
            payload["signals"] = signals[:5]
            hits.append(payload)

    result["misses"] = misses
    result["hits"] = hits
    result["miss_count"] = len(misses)
    result["hit_count"] = len(hits)

    print(f"[attacker] {args.category}: {len(hits)} detected, {len(misses)} missed by scanner")
    for m in misses:
        print(f"  MISS [{m['id']}]: {m['text'][:80]}...")

    if args.output:
        Path(args.output).write_text(json.dumps(result, indent=2))
        print(f"[attacker] Results written to {args.output}")
    else:
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
