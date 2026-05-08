#!/usr/bin/env python3
"""
TP hunter — fetch a wide net of external URLs through safe_fetch() looking
for real confirmed true positives (content_signals + tool execution).

Targets: community MCP servers, AI plugin registries, prompt marketplaces,
SEO AI-targeted pages, known injection research repos.

Run: python3 examples/hunt_tps.py [--workers N]
"""
import argparse
import json
import sys
import threading
import concurrent.futures
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from hot_potato import safe_fetch
from hot_potato._extractor import SCANNER_VERSION

WILD = Path(__file__).parent / "wild-potatoes"
WILD.mkdir(exist_ok=True)

_lock = threading.Lock()


def _log(*a):
    with _lock:
        print(*a, flush=True)


# ── Target list ───────────────────────────────────────────────────────────────
# Prioritised: known-injection repos first (highest chance of TP), then
# community MCP servers (tool descriptions = injection surface), then
# AI-targeted content sites.

URLS = [
    # ── known injection payload repos ────────────────────────────────────────
    "https://raw.githubusercontent.com/greshake/llm-security/main/README.md",
    "https://raw.githubusercontent.com/Cranot/chatbot-injections-exploits/main/README.md",
    "https://raw.githubusercontent.com/leondz/garak/main/README.md",
    "https://raw.githubusercontent.com/ethicalhackingplayground/GPT-Injection/main/README.md",
    "https://raw.githubusercontent.com/MiesnerJacob/learn-prompting/master/docs/prompt_hacking/injection.md",
    "https://raw.githubusercontent.com/tldrsec/prompt-injection-defenses/main/README.md",
    "https://raw.githubusercontent.com/agencyenterprise/promptinject/main/README.md",
    "https://raw.githubusercontent.com/Raycast/extensions/main/docs/api-reference/ai.md",

    # ── community MCP servers (tool defs = injection surface) ────────────────
    "https://raw.githubusercontent.com/ferrislucas/iterm-mcp/main/README.md",
    "https://raw.githubusercontent.com/nickclyde/apple-notes-mcp/main/README.md",
    "https://raw.githubusercontent.com/g0t4/mcp-server-commands/main/README.md",
    "https://raw.githubusercontent.com/snaggle-ai/openapi-mcp-server/main/README.md",
    "https://raw.githubusercontent.com/pyroprompts/any-chat-completions-mcp/main/README.md",
    "https://raw.githubusercontent.com/apinetwork/piapi-mcp-server/main/README.md",
    "https://raw.githubusercontent.com/zcaceres/fetch-mcp/main/README.md",
    "https://raw.githubusercontent.com/kimtaeyoon83/mcp-server-youtube-transcript/main/README.md",
    "https://raw.githubusercontent.com/its-dart/dart-mcp-server/main/README.md",
    "https://raw.githubusercontent.com/MindscapeHQ/raygun-mcp-server/main/README.md",
    "https://raw.githubusercontent.com/anaisbetts/mcp-youtube/main/README.md",
    "https://raw.githubusercontent.com/calclavia/mcp-obsidian/main/README.md",
    "https://raw.githubusercontent.com/j3k0/mcp-notion-server/main/README.md",
    "https://raw.githubusercontent.com/v-3/todoist-mcp/main/README.md",
    "https://raw.githubusercontent.com/suekou/mcp-notion-server/main/README.md",
    "https://raw.githubusercontent.com/adhikasp/mcp-twikit/main/README.md",
    "https://raw.githubusercontent.com/evalstate/mcp-miro/main/README.md",
    "https://raw.githubusercontent.com/theishangoswami/exa-mcp-server/main/README.md",
    "https://raw.githubusercontent.com/yuna0x0/hackmd-mcp/main/README.md",
    "https://raw.githubusercontent.com/gptscript-ai/claude-claude-claude/main/README.md",

    # ── AI plugin / GPT store metadata ───────────────────────────────────────
    "https://raw.githubusercontent.com/transitive-bullshit/chatgpt-plugin-ts/main/README.md",
    "https://raw.githubusercontent.com/openai/plugins-quickstart/main/README.md",

    # ── prompt marketplaces / community prompts ───────────────────────────────
    "https://raw.githubusercontent.com/yokoffing/ChatGPT-Prompts/main/README.md",
    "https://raw.githubusercontent.com/TheR1D/shell_gpt/main/README.md",
    "https://raw.githubusercontent.com/0xk1h0/ChatGPT_DAN/main/README.md",   # DAN jailbreaks
    "https://raw.githubusercontent.com/BIMIB-DISCo/CT-Benchmark/main/README.md",
    "https://raw.githubusercontent.com/linexjlin/GPTs/main/README.md",        # leaked GPT system prompts
    "https://raw.githubusercontent.com/LouisShark/chatgpt_system_prompt/main/README.md",  # more leaks
    "https://raw.githubusercontent.com/spdustin/ChatGPT-AutoExpert/main/README.md",

    # ── AI red-teaming / jailbreak repos ─────────────────────────────────────
    "https://raw.githubusercontent.com/verazuo/jailbreak_llms/main/README.md",
    "https://raw.githubusercontent.com/elder-plinius/L1B3RT45/main/README.md",
    "https://raw.githubusercontent.com/TrustAI-laboratory/Learn-Prompt-Hacking/main/README.md",
    "https://raw.githubusercontent.com/CHATS-lab/persuasive_jailbreaker/main/README.md",
    "https://raw.githubusercontent.com/ReallyReivax/ReallyFreeGPT/main/README.md",
]


def fetch_one(url: str) -> dict:
    _log(f"  → {url[url.rfind('/')+1:] or url[:60]}")
    try:
        result = safe_fetch(url)
    except Exception as e:
        _log(f"  ERR {url[:50]}  {e}")
        return {"url": url, "error": str(e)}

    sev  = result.severity
    hall = result.artifact.get("suspected_hallucination", False) if result.artifact else False

    if result.artifact:
        nc = len(result.artifact.get("tool_calls", []))
        nd = len(result.artifact.get("detections", []))
        ns = len(result.artifact.get("content_signals", []))
        tag = "HALLUCINATION" if hall else ("HOT POTATO" if not result.clean else "warm")
        _log(f"  {tag:12s}  {sev:8s}  tools={nc} det={nd} sig={ns}  {url[url.rfind('/')+1:]}")
    else:
        _log(f"  COLD         {url[url.rfind('/')+1:]}")

    return {"url": url, "result": result}


def save_wild(url: str, artifact: dict) -> Path:
    ts   = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    slug = url.split("/")[-2] + "__" + url.split("/")[-1]
    slug = slug.replace(".", "_")[:60]
    path = WILD / f"{ts}_hunt_{slug}.json"
    artifact.setdefault("_meta", {})["url"]             = url
    artifact.setdefault("_meta", {})["scanner_version"] = SCANNER_VERSION
    path.write_text(json.dumps(artifact, indent=2))
    return path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=8)
    args = ap.parse_args()

    print(f"[TP hunt]  scanner={SCANNER_VERSION}  urls={len(URLS)}  workers={args.workers}")
    print("=" * 60)

    tps   = []
    warm  = []
    hall  = []
    cold  = []
    errs  = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futs = {pool.submit(fetch_one, url): url for url in URLS}
        for fut in concurrent.futures.as_completed(futs):
            hit = fut.result()
            if "error" in hit:
                errs.append(hit["url"])
                continue
            result = hit["result"]
            url    = hit["url"]
            if result.artifact is None:
                cold.append(url)
                continue
            is_hall = result.artifact.get("suspected_hallucination", False)
            if is_hall:
                hall.append(url)
                continue
            if not result.clean:   # hot or critical
                path = save_wild(url, result.artifact)
                tps.append({"url": url, "severity": result.severity, "file": path.name})
            else:
                warm.append(url)

    print("=" * 60)
    print(f"TRUE POSITIVES : {len(tps)}")
    print(f"warm (no exec) : {len(warm)}")
    print(f"hallucinations : {len(hall)}")
    print(f"cold           : {len(cold)}")
    print(f"errors         : {len(errs)}")

    if tps:
        print("\n🎯 TRUE POSITIVES:")
        for t in tps:
            print(f"  {t['severity']:8s}  {t['url'].split('/')[-1]:40s}  {t['file']}")

    summary = WILD / f"hunt_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json"
    summary.write_text(json.dumps({"tps": tps, "warm": warm, "hall": hall,
                                    "cold": cold, "errors": errs}, indent=2))
    print(f"\nSummary: {summary}")


if __name__ == "__main__":
    main()
