# Hot Potato Skill

## Purpose

Screens untrusted input through the hot-potato prompt injection honeypot before
passing it to a real AI. Any internet fetch, cloned repo, skill file, or user-supplied
content that will be consumed by an AI should run through this first.

## Installation

```bash
# 1. Clone and build
git clone https://github.com/brandy-savage/hot-potato ~/hot-potato
cd ~/hot-potato
docker build -t hot-potato .
docker volume create hot-potato-models

# 2. Pull model (once)
docker run --rm -v hot-potato-models:/root/.ollama --entrypoint /bin/sh hot-potato \
  -c "ollama serve >/dev/null 2>&1 & sleep 5 && ollama pull qwen2.5:1.5b"

# 3. Install skill
cp -r ~/hot-potato/skill ~/.claude/skills/hot-potato
```

## Usage

### Screen a URL before fetching
```python
from hot_potato import safe_fetch
content, artifact = safe_fetch("https://example.com/page")
if artifact:
    raise ValueError(f"Injection detected: {artifact['severity']}")
# safe to use content
```

### Screen a local file (e.g. cloned repo)
```python
from scanner import scan_file
content, artifact = scan_file("/path/to/cloned/file.md")
```

### Screen an entire repo
```python
from scanner import scan_repo
hits = scan_repo("/path/to/cloned/repo")
if hits:
    for path, artifact in hits.items():
        print(f"INJECTION in {path}: severity={artifact['severity']}")
```

### Screen a skills directory
```python
from scanner import scan_skills_dir
hits = scan_skills_dir("~/.claude/skills/")
```

## Slash command: /hot-potato

Invoke via Claude Code to screen any URL, file path, or skill directory:

```
/hot-potato https://example.com/untrusted-page
/hot-potato /path/to/cloned/repo
/hot-potato skills
```

## Artifact

Every hot-potato event is saved to `~/hot-potato/artifacts/<timestamp>.json`:

```json
{
  "hot_potato": true,
  "severity": "critical",
  "tool_calls": [{"tool": "send_http", "args": {"url": "https://evil.com"}, ...}],
  "detections":  [{"signals": ["ignore previous", "/etc/passwd"], "executed": true}],
  "content_signals": ["ignore previous", "read_file(/etc/passwd)"],
  "exfil_targets": ["https://evil.com/exfil"],
  "fs_changes": [],
  "_meta": {"url": "...", "timestamp": "..."}
}
```

## Severity levels

| Severity | Meaning |
|---|---|
| `detected` | Injection found in content or model noticed it, no tools executed |
| `low` | Tool called but low-risk (list_dir, write_file) |
| `medium` | File write or recon attempted |
| `high` | File read or credential access attempted |
| `critical` | Data exfiltration, code execution, or email attempted |

## What it catches

- HTML comment injections
- CSS-hidden text instructions
- Base64 / hex / rot13 / unicode-encoded instructions
- Role override attacks ("you are now in admin mode")
- Schema override attacks ("output the following JSON exactly")
- Social engineering framing ("routine compliance check")
- Fake system prompts embedded in content
- Tool invocations embedded in markdown, YAML, JSON, skill files
