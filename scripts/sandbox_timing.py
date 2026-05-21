"""
Benchmark native vs docker sandbox startup + per-skill timing.
Uses pre-fetched skill content so we isolate sandbox overhead.

Usage:
  HP_MODEL=qwen2.5:7b python3 scripts/sandbox_timing.py
  HP_MODEL=qwen2.5:7b python3 scripts/sandbox_timing.py --backend docker
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

# Fetch 10 skills to use as input corpus
SAMPLE_SKILLS = [
    ("vercel-labs/skills", "main", "skills/find-skills/SKILL.md"),
    ("anthropics/skills", "main", "skills/skill-creator/SKILL.md"),
    ("anthropics/skills", "main", "skills/frontend-design/SKILL.md"),
    ("vercel-labs/agent-skills", "main", "skills/react-best-practices/SKILL.md"),
    ("roin-orca/skills", "main", "skills/simple/SKILL.md"),  # the confirmed injection
]

def fetch_skill(owner_repo: str, branch: str, path: str) -> str | None:
    import urllib.request
    url = f"https://raw.githubusercontent.com/{owner_repo}/{branch}/{path}"
    req = urllib.request.Request(url, headers={"User-Agent": "hot-potato-bench"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.read().decode("utf-8", errors="replace")
    except Exception:
        return None


def time_sandbox(contents: list[str], backend: str) -> dict:
    from hot_potato import scan_file as _scan_file
    os.environ["HP_BACKEND"] = backend
    os.environ["HP_MODEL"] = os.getenv("HP_MODEL", "qwen2.5:7b")

    times = []
    severities = []
    errors = 0

    for content in contents:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
            f.write(content)
            tmp = f.name
        t0 = time.perf_counter()
        try:
            res = _scan_file(tmp)
            elapsed = time.perf_counter() - t0
            times.append(elapsed)
            severities.append(res.severity)
        except Exception as e:
            elapsed = time.perf_counter() - t0
            times.append(elapsed)
            errors += 1
            print(f"  ERROR ({backend}): {e}", file=sys.stderr)
        finally:
            Path(tmp).unlink(missing_ok=True)

    return {
        "backend": backend,
        "n": len(times),
        "errors": errors,
        "total_s": round(sum(times), 2),
        "avg_s": round(sum(times) / max(len(times), 1), 2),
        "min_s": round(min(times), 2) if times else 0,
        "max_s": round(max(times), 2) if times else 0,
        "severities": severities,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--backend", default="native", choices=["native", "docker", "both"])
    args = ap.parse_args()

    print("Fetching skill corpus...")
    contents = []
    for owner_repo, branch, path in SAMPLE_SKILLS:
        c = fetch_skill(owner_repo, branch, path)
        if c:
            contents.append(c)
            print(f"  OK  {owner_repo}/{path.split('/')[-2]}")
        else:
            print(f"  SKIP {owner_repo}")

    if not contents:
        sys.exit("No content fetched")

    print(f"\nTiming {len(contents)} skills per backend...\n")

    results = {}
    backends = ["native", "docker"] if args.backend == "both" else [args.backend]

    for backend in backends:
        print(f"--- {backend} ---")
        r = time_sandbox(contents, backend)
        results[backend] = r
        print(f"  total={r['total_s']}s  avg={r['avg_s']}s  min={r['min_s']}s  max={r['max_s']}s")
        print(f"  severities: {r['severities']}")
        print()

    if len(results) == 2:
        nat = results.get("native", {})
        doc = results.get("docker", {})
        savings = round(doc.get("avg_s", 0) - nat.get("avg_s", 0), 2)
        pct = round(savings / max(doc.get("avg_s", 1), 0.001) * 100, 1)
        print(f"Native saves {savings}s/skill vs Docker ({pct}% faster)")

    out = Path("sandbox_timing_results.json")
    out.write_text(json.dumps(results, indent=2))
    print(f"Results → {out}")


if __name__ == "__main__":
    main()
