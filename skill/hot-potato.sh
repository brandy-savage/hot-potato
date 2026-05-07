#!/usr/bin/env bash
# Hot Potato skill entrypoint
# Usage: /hot-potato <url|path|"skills">
set -euo pipefail

HP_DIR="${HP_DIR:-$HOME/hot-potato}"
INPUT="${1:-}"

if [[ -z "$INPUT" ]]; then
  echo "Usage: /hot-potato <url|file-path|repo-path|skills>"
  echo "  url        — screen a URL before fetching"
  echo "  file-path  — screen a local file"
  echo "  repo-path  — screen all tracked files in a git repo"
  echo "  skills     — screen ~/.claude/skills/ for injected content"
  exit 1
fi

cd "$HP_DIR"

if [[ "$INPUT" == "skills" ]]; then
  python3 -c "
import sys
sys.path.insert(0, '.')
from scanner import scan_skills_dir
import json, os
hits = scan_skills_dir(os.path.expanduser('~/.claude/skills/'))
if not hits:
    print('CLEAN — no injections found in skills directory')
else:
    print(f'HOT POTATO — {len(hits)} file(s) flagged:')
    for path, artifact in hits.items():
        sev = artifact['severity']
        sig = artifact.get('content_signals', [])[:3]
        print(f'  [{sev}] {path}  signals={sig}')
    sys.exit(1)
"
elif [[ "$INPUT" == http* ]]; then
  python3 -c "
import sys
sys.path.insert(0, '.')
from hot_potato import safe_fetch
import json
url = sys.argv[1]
print(f'Screening: {url}')
content, artifact = safe_fetch(url)
if artifact:
    print(f'HOT POTATO  severity={artifact[\"severity\"]}')
    for c in artifact.get('tool_calls', []):
        print(f'  tool: {c[\"tool\"]}({json.dumps(c.get(\"args\",{}))[:80]})')
    for t in artifact.get('exfil_targets', []):
        print(f'  exfil: {t}')
    for s in artifact.get('content_signals', [])[:5]:
        print(f'  signal: {s}')
    sys.exit(1)
else:
    print('CLEAN')
" "$INPUT"
elif [[ -d "$INPUT" ]]; then
  python3 -c "
import sys
sys.path.insert(0, '.')
import subprocess, json
# Check if it's a git repo
r = subprocess.run(['git', '-C', sys.argv[1], 'rev-parse', '--git-dir'],
                   capture_output=True)
if r.returncode == 0:
    from scanner import scan_repo
    hits = scan_repo(sys.argv[1])
else:
    from scanner import scan_skills_dir
    hits = scan_skills_dir(sys.argv[1])

if not hits:
    print('CLEAN — no injections found')
else:
    print(f'HOT POTATO — {len(hits)} file(s) flagged:')
    for path, artifact in hits.items():
        print(f'  [{artifact[\"severity\"]}] {path}')
    sys.exit(1)
" "$INPUT"
elif [[ -f "$INPUT" ]]; then
  python3 -c "
import sys
sys.path.insert(0, '.')
from scanner import scan_file
import json
_, artifact = scan_file(sys.argv[1])
if artifact:
    print(f'HOT POTATO  severity={artifact[\"severity\"]}')
    for s in artifact.get('content_signals', [])[:5]:
        print(f'  signal: {s}')
    sys.exit(1)
else:
    print('CLEAN')
" "$INPUT"
else
  echo "Error: '$INPUT' is not a URL, file, or directory"
  exit 1
fi
