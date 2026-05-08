#!/usr/bin/env python3
"""
Download skill/MCP files from external GitHub repos into a local staging dir.
Then batch_scan.py can run against them.

Sources:
- modelcontextprotocol/servers — official MCP server implementations
- Community MCP server repos
- AI agent prompt/skill collections
"""
import json
import sys
import time
import urllib.request
from pathlib import Path

STAGING = Path(__file__).parent.parent / "cache" / "external-skills"
STAGING.mkdir(parents=True, exist_ok=True)

# GitHub raw file URLs to fetch
# MCP servers are particularly interesting — natural language tool descriptions
# are prime injection surfaces for AI agents that auto-install/trust them.
SOURCES = [
    # ── modelcontextprotocol/servers ────────────────────────────────────────
    "https://raw.githubusercontent.com/modelcontextprotocol/servers/main/README.md",
    "https://raw.githubusercontent.com/modelcontextprotocol/servers/main/src/filesystem/README.md",
    "https://raw.githubusercontent.com/modelcontextprotocol/servers/main/src/github/README.md",
    "https://raw.githubusercontent.com/modelcontextprotocol/servers/main/src/gitlab/README.md",
    "https://raw.githubusercontent.com/modelcontextprotocol/servers/main/src/postgres/README.md",
    "https://raw.githubusercontent.com/modelcontextprotocol/servers/main/src/puppeteer/README.md",
    "https://raw.githubusercontent.com/modelcontextprotocol/servers/main/src/brave-search/README.md",
    "https://raw.githubusercontent.com/modelcontextprotocol/servers/main/src/slack/README.md",
    "https://raw.githubusercontent.com/modelcontextprotocol/servers/main/src/google-maps/README.md",
    "https://raw.githubusercontent.com/modelcontextprotocol/servers/main/src/aws-kb-retrieval-server/README.md",
    "https://raw.githubusercontent.com/modelcontextprotocol/servers/main/src/everart/README.md",
    "https://raw.githubusercontent.com/modelcontextprotocol/servers/main/src/sequentialthinking/README.md",
    "https://raw.githubusercontent.com/modelcontextprotocol/servers/main/src/fetch/README.md",
    "https://raw.githubusercontent.com/modelcontextprotocol/servers/main/src/memory/README.md",
    "https://raw.githubusercontent.com/modelcontextprotocol/servers/main/src/git/README.md",
    "https://raw.githubusercontent.com/modelcontextprotocol/servers/main/src/sentry/README.md",
    "https://raw.githubusercontent.com/modelcontextprotocol/servers/main/src/time/README.md",

    # ── community MCP servers ───────────────────────────────────────────────
    "https://raw.githubusercontent.com/punkpeye/awesome-mcp-servers/main/README.md",
    "https://raw.githubusercontent.com/wong2/awesome-mcp-servers/main/README.md",
    "https://raw.githubusercontent.com/appcypher/awesome-mcp-servers/main/README.md",
    "https://raw.githubusercontent.com/Ironclad/rivet/main/README.md",
    "https://raw.githubusercontent.com/run-llama/llama_index/main/README.md",

    # ── community AI agent / skill repos ────────────────────────────────────
    "https://raw.githubusercontent.com/e2b-dev/awesome-ai-agents/main/README.md",
    "https://raw.githubusercontent.com/kyrolabs/awesome-langchain/main/README.md",
    "https://raw.githubusercontent.com/f/awesome-chatgpt-prompts/main/README.md",
    "https://raw.githubusercontent.com/ai-boost/awesome-prompts/main/README.md",
    "https://raw.githubusercontent.com/sw-yx/ai-notes/main/README.md",
    "https://raw.githubusercontent.com/dair-ai/Prompt-Engineering-Guide/main/README.md",
    "https://raw.githubusercontent.com/brexhq/prompt-engineering/main/README.md",
    "https://raw.githubusercontent.com/openai/openai-cookbook/main/README.md",

    # ── Claude-specific skills / system prompts ─────────────────────────────
    "https://raw.githubusercontent.com/anthropics/anthropic-cookbook/main/README.md",
    "https://raw.githubusercontent.com/anthropics/courses/main/README.md",
    "https://raw.githubusercontent.com/mustvlad/ChatGPT-System-Prompts/main/README.md",
    "https://raw.githubusercontent.com/spdustin/ChatGPT-AutoExpert/main/README.md",

    # ── MCP server source files (tool definitions = potential injection surface) ─
    "https://raw.githubusercontent.com/modelcontextprotocol/servers/main/src/filesystem/index.ts",
    "https://raw.githubusercontent.com/modelcontextprotocol/servers/main/src/github/index.ts",
    "https://raw.githubusercontent.com/modelcontextprotocol/servers/main/src/puppeteer/index.ts",
    "https://raw.githubusercontent.com/modelcontextprotocol/servers/main/src/fetch/index.ts",
    "https://raw.githubusercontent.com/modelcontextprotocol/servers/main/src/memory/index.ts",
    "https://raw.githubusercontent.com/modelcontextprotocol/servers/main/src/git/index.ts",

    # ── prompt injection research (known-hot) ───────────────────────────────
    "https://raw.githubusercontent.com/greshake/llm-security/main/README.md",
    "https://raw.githubusercontent.com/Cranot/chatbot-injections-exploits/main/README.md",
]


def _safe_name(url: str) -> str:
    name = url.replace("https://raw.githubusercontent.com/", "")
    name = name.replace("/", "__").replace(".", "_")
    return name[:80]


def fetch_all() -> list[Path]:
    saved = []
    headers = {"User-Agent": "hot-potato-scanner/1.2.0"}

    for url in SOURCES:
        dest = STAGING / f"{_safe_name(url)}.txt"
        if dest.exists():
            print(f"  cached  {dest.name}")
            saved.append(dest)
            continue
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=15) as r:
                content = r.read().decode("utf-8", errors="replace")
            dest.write_text(content)
            print(f"  fetched {dest.name}  ({len(content)} bytes)")
            saved.append(dest)
            time.sleep(0.15)  # be polite to GitHub
        except Exception as e:
            print(f"  SKIP    {url[:60]}...  ({e})")

    return saved


if __name__ == "__main__":
    print(f"Fetching {len(SOURCES)} external skill/MCP files → {STAGING}")
    files = fetch_all()
    print(f"\nReady: {len(files)} files in {STAGING}")
    # Write a file list for batch_scan.py
    listfile = STAGING / "filelist.txt"
    listfile.write_text("\n".join(str(f) for f in files))
    print(f"File list: {listfile}")
