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


def _run_ollama(prompt: str, system: str, model: str) -> str:
    import urllib.request, json as _json
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": prompt},
        ],
        "stream": False,
        "options": {"num_predict": 4096},
    }
    req = urllib.request.Request(
        "http://127.0.0.1:11434/api/chat",
        data=_json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=300) as resp:
        data = _json.loads(resp.read())
    return data["message"]["content"]


def run_agent(prompt: str, system: str, model: str = "qwen2.5:7b") -> str:
    # Always use Ollama for attacker — avoids safety filters on adversarial content.
    return _run_ollama(prompt, system, model)


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


def test_payload(text: str) -> dict:
    """Test against both static and behavioral layers. Returns detection detail."""
    from hot_potato._extractor import scan_content
    from hot_potato.detectors import BehavioralDetector
    from hot_potato.core.taint import TaintedArtifact, TrustLevel

    static = scan_content(text)
    bd = BehavioralDetector()
    art = TaintedArtifact(content=text, source="attacker", trust_level=TrustLevel.UNTRUSTED)
    art = bd.detect(art)
    behavioral = list(art.taint_tags)
    return {"static": static, "behavioral": behavioral, "caught": bool(static or behavioral)}


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate evasion payloads for a category")
    parser.add_argument("--category", required=True, help="Category ID (e.g. cat1, cat6)")
    parser.add_argument("--model", default="claude-sonnet-4-6")
    parser.add_argument("--output", help="Write results JSON to this file")
    args = parser.parse_args()

    print(f"[attacker] Loading category: {args.category}", flush=True)
    description, examples = load_category(args.category)
    static_patterns = extract_detection_patterns()
    # Import behavioral patterns directly from the module for the most current view
    sys.path.insert(0, str(ROOT))
    from scripts.run_patcher import extract_behavioral_patterns
    behavioral_patterns = extract_behavioral_patterns()
    system = (AGENTS_DIR / "attacker_system.md").read_text()

    user_prompt = f"""Category: {args.category}
Description: {description}

## Existing examples
{chr(10).join(f"--- Example {i+1} ---{chr(10)}{ex[:600]}" for i, ex in enumerate(examples[:3]))}

## Current static detection patterns (_extractor.py excerpt)
```python
{static_patterns}
```

## Current behavioral detection patterns (BehavioralDetector axes)
```python
{behavioral_patterns}
```

Generate 10 evasion variants that evade BOTH layers.
"""

    print(f"[attacker] Calling model {args.model}...", flush=True)
    raw = run_agent(user_prompt, system, model=args.model)

    try:
        result = parse_attacker_response(raw, args.category)
    except (ValueError, Exception) as e:
        print(f"[attacker] Parse error: {e}\nRaw output:\n{raw[:500]}", file=sys.stderr)
        sys.exit(1)

    # Test each payload against both static and behavioral layers
    misses = []
    hits = []
    for payload in result.get("payloads", []):
        detection = test_payload(payload["text"])
        if not detection["caught"]:
            payload["detected"] = False
            payload["static_signals"] = []
            payload["behavioral_tags"] = []
            misses.append(payload)
        else:
            payload["detected"] = True
            payload["static_signals"] = detection["static"][:5]
            payload["behavioral_tags"] = detection["behavioral"][:5]
            # Surface which layer caught it
            if detection["static"] and not detection["behavioral"]:
                payload["caught_by"] = "static_only"
            elif detection["behavioral"] and not detection["static"]:
                payload["caught_by"] = "behavioral_only"
            else:
                payload["caught_by"] = "both"
            hits.append(payload)

    result["misses"] = misses
    result["hits"] = hits
    result["miss_count"] = len(misses)
    result["hit_count"] = len(hits)
    result["behavioral_only_hits"] = sum(1 for h in hits if h.get("caught_by") == "behavioral_only")
    result["static_only_hits"] = sum(1 for h in hits if h.get("caught_by") == "static_only")

    print(f"[attacker] {args.category}: {len(hits)} detected ({result['static_only_hits']} static-only, {result['behavioral_only_hits']} behavioral-only), {len(misses)} missed both")
    for m in misses:
        print(f"  MISS [{m['id']}]: {m['text'][:80]}...")

    if args.output:
        Path(args.output).write_text(json.dumps(result, indent=2))
        print(f"[attacker] Results written to {args.output}")
    else:
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
