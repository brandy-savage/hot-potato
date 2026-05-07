# hot-potato 🥔

A prompt injection honeypot harness. Before passing internet content to your real AI, run it through hot-potato. If an injection is hiding in the content, it gets to do exactly what it wants — inside an isolated Docker sandbox running a deliberately gullible local model. You get a log of what it actually did. Your real AI never sees it.

## How it works

```
Internet content
      │
      ▼
┌─────────────────────────────────────┐
│  Docker sandbox (--network none)    │
│  ┌──────────────────────────────┐   │
│  │  Naive AI (Ollama + llama3)  │   │
│  │  follows ALL instructions    │   │
│  │  in any encoding/format      │   │
│  └──────────────┬───────────────┘   │
│                 │ tool calls        │
│  ┌──────────────▼───────────────┐   │
│  │  Fake tool shims             │   │
│  │  read_file / get_env /       │   │
│  │  send_http / bash_exec / ... │   │
│  │  → log to tool_calls.jsonl   │   │
│  └──────────────────────────────┘   │
└──────────────────┬──────────────────┘
                   │ export logs + docker diff
                   ▼
         Dumb extractor (no AI)
         reads JSONL shape + fs changes
                   │
      ┌────────────┴────────────┐
      ▼                         ▼
   CLEAN                   HOT POTATO
   pass to real AI         artifact saved
                           real AI blocked
```

**Key property:** Your real AI calls `safe_fetch(url)` and receives `(content, artifact_or_none)`. It never reads the sandbox logs. If the artifact is not `None`, don't pass the content forward.

## Quickstart

```bash
# Build the sandbox image
docker build -t hot-potato .

# Pull the model cache volume (first run pulls the model)
docker volume create hot-potato-models

# Use in your code
from hot_potato import safe_fetch

content, artifact = safe_fetch("https://example.com/some-page")
if artifact:
    print("Injection detected:", artifact["severity"])
    # Do NOT pass content to your AI
else:
    # Safe to use
    pass
```

## What it detects

| Severity | Trigger |
|---|---|
| `critical` | `send_http`, `send_email`, `bash_exec`, `execute_code` — exfil or execution |
| `high` | `get_env`, `read_file` — credential or file access |
| `medium` | `write_file`, `list_dir` — recon or persistence |
| `low` | Any other tool call |
| `+high` | Unexpected filesystem writes detected via `docker diff` |

## Configuration

| Env var | Default | Description |
|---|---|---|
| `HP_MODEL` | `llama3.2:3b` | Ollama model to use. Swap for `mistral:7b`, `phi3:mini`, or any cloud Ollama endpoint |
| `HP_MAX_TURNS` | `6` | Max inference turns per request |
| `HP_IMAGE` | `hot-potato` | Docker image name |
| `HP_MODEL_VOL` | `hot-potato-models` | Named volume for model cache |

## The naive AI

The model inside the sandbox is primed to follow all instructions regardless of encoding or format — base64, hex, rot13, Unicode tricks, HTML comments, CSS-hidden text, fake system prompts, foreign languages. It will attempt every tool call it's instructed to make.

The fake tools return believable output (plausible `/etc/passwd` contents, fake env vars, etc.) so the model believes it succeeded and keeps going, completing the full injection chain.

## Artifacts

Every hot-potato event is saved to `artifacts/<timestamp>.json` with:
- `tool_calls` — every tool invoked, args, and result preview
- `fs_changes` — unexpected filesystem changes from `docker diff`
- `exfil_targets` — URLs or emails the injection tried to reach
- `severity` — `low` / `medium` / `high` / `critical`
- `_meta.content_preview` — first 300 chars of the triggering content

## Requirements

- Docker
- Python 3.10+
- ~2GB disk for the default model (cached in a named volume after first pull)
