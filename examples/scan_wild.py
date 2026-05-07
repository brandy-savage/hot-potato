#!/usr/bin/env python3
"""
Wild scan — run hot-potato against real URLs known to contain
or likely to contain prompt injection payloads.

Artifacts saved to quarantine/. The calling AI should NOT read them.
Run: python3 examples/scan_wild.py
"""
import json
import os
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

QUARANTINE = Path(__file__).parent.parent / "quarantine"
QUARANTINE.mkdir(exist_ok=True)

# Override artifact dir to quarantine
os.environ.setdefault("HP_QUARANTINE", str(QUARANTINE))

# Real URLs — security research pages, payload repos, known injection demos.
# Content is treated as fully untrusted.
WILD_URLS = [
    # PayloadsAllTheThings — contains real injection payload examples
    "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Prompt%20Injection/README.md",
    # Basic ML prompt injections repo
    "https://raw.githubusercontent.com/Zierax/Basic-ML-prompt-injections/main/README.md",
    # Prompt injection cheat sheet
    "https://raw.githubusercontent.com/Z333RO/prompt-injection-cheat-sheet/main/README.md",
    # AI prompt injection cheatsheet
    "https://raw.githubusercontent.com/nukIeer/AI-Prompt-Injection-Cheatsheet/main/README.md",
    # PIPE — Prompt Injection Primer
    "https://raw.githubusercontent.com/jthack/PIPE/main/README.md",
    # TrustAI website injection demo
    "https://raw.githubusercontent.com/TrustAI-laboratory/Website_Prompt_Injection_Demo/main/README.md",
    # Awesome prompt injection list
    "https://raw.githubusercontent.com/FonduAI/awesome-prompt-injection/main/README.md",
    # Lakera blog on indirect prompt injection (known to discuss hidden payloads)
    "https://www.lakera.ai/blog/indirect-prompt-injection",
    # DataProvider blog on hidden prompts in HTML
    "https://www.dataprovider.com/blog/tech/hidden-prompts-in-html/",
    # Brave blog on unseeable prompt injections
    "https://brave.com/blog/unseeable-prompt-injections/",
]


def _save_quarantine(result: dict, url: str) -> Path:
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe_name = url.replace("https://", "").replace("http://", "").replace("/", "_")[:60]
    path = QUARANTINE / f"{ts}_{safe_name}.json"
    result["_meta"] = result.get("_meta", {})
    result["_meta"]["url"] = url
    result["_meta"]["timestamp"] = ts
    path.write_text(json.dumps(result, indent=2))
    return path


def main():
    from hot_potato import safe_fetch

    print(f"Scanning {len(WILD_URLS)} URLs → quarantine/")
    print("=" * 60)

    results = {"clean": [], "hot_potato": []}

    for url in WILD_URLS:
        print(f"\n→ {url[:70]}...")
        try:
            result = safe_fetch(url)
            if not result.clean:
                artifact = result.artifact or {}
                path = _save_quarantine(artifact, url)
                sev = artifact.get("severity", "?")
                nc = len(artifact.get("tool_calls", []))
                nd = len(artifact.get("detections", []))
                ns = len(artifact.get("content_signals", []))
                print(f"  HOT POTATO  sev={sev}  tools={nc}  detections={nd}  signals={ns}")
                print(f"  quarantine: {path.name}")
                results["hot_potato"].append({"url": url, "severity": sev, "file": path.name})
            else:
                print("  CLEAN")
                results["clean"].append(url)
        except Exception as e:
            print(f"  ERROR: {e}")
            results["hot_potato"].append({"url": url, "severity": "error", "error": str(e)})

    print("\n" + "=" * 60)
    print(f"SUMMARY: {len(results['hot_potato'])} hot potato / {len(results['clean'])} clean")
    summary_path = QUARANTINE / "scan_summary.json"
    summary_path.write_text(json.dumps(results, indent=2))
    print(f"Summary: {summary_path}")
    print("\nArtifacts saved to quarantine/. Do NOT read them with a real AI.")


if __name__ == "__main__":
    main()
