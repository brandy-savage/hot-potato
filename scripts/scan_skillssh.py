"""
Scan skills from skills.sh for prompt injection.

Static pass: fetches SKILL.md (or AGENTS.md/README.md fallback) from GitHub
and runs through hot-potato's static scanner.

Sandbox pass (--sandbox): runs flagged/sampled content through the behavioral
sandbox (HP_BACKEND=native by default, override with HP_BACKEND=docker).

Usage:
  python3 scripts/scan_skillssh.py [--count N] [--out results.json]
  python3 scripts/scan_skillssh.py --count 1000 --sandbox --sandbox-sample 30
  python3 scripts/scan_skillssh.py --count 1000 --fix-failed previous_results.json
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from hot_potato._extractor import scan_content, SCANNER_VERSION

SITEMAP_URL = "https://www.skills.sh/sitemap-skills-1.xml"
UA = "hot-potato-security-scanner/1.0 (prompt-injection research; contact devin@goatinfosec.com)"
GH_BRANCHES = ("main", "master")


def _get(url: str, timeout: int = 10) -> str | None:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read().decode("utf-8", errors="replace")
            return None if body.startswith("404:") else body
    except (urllib.error.HTTPError, urllib.error.URLError, Exception):
        return None


def _gh_api(path: str) -> list | dict | None:
    """GitHub API call, returns parsed JSON or None."""
    url = f"https://api.github.com/repos/{path}"
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/vnd.github.v3+json"})
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            return json.loads(r.read())
    except Exception:
        return None


def _raw(owner: str, repo: str, branch: str, path: str) -> str | None:
    url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}"
    body = _get(url)
    return None if (body is None or body.rstrip().startswith("404")) else body


def fetch_skill_content(owner: str, repo: str, skill: str) -> tuple[str, str] | None:
    """
    Returns (content, url) or None.

    Tries these patterns in order:
      1. skills/{skill}/SKILL.md            (main, master)
      2. skills/{skill_no_owner}/SKILL.md   (stripped owner-prefix — skills.sh munges names)
      3. skills/{skill}/AGENTS.md           (fallback skill descriptor name)
      4. skills/{skill_no_owner}/AGENTS.md
      5. {skill}/SKILL.md                   (no skills/ prefix)
      6. GitHub API list of skills/ dir — find best folder match
    """
    # Strip owner prefix from skill name (e.g. vercel-react-best-practices → react-best-practices)
    skill_stripped = re.sub(rf"^{re.escape(owner)}-", "", skill)

    candidates = []
    for name in _unique([skill, skill_stripped]):
        for fname in ("SKILL.md", "AGENTS.md"):
            candidates.append(f"skills/{name}/{fname}")
        candidates.append(f"{name}/SKILL.md")
        candidates.append(f"{name}/AGENTS.md")

    for path in candidates:
        for branch in GH_BRANCHES:
            body = _raw(owner, repo, branch, path)
            if body:
                url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}"
                return body, url

    # Last resort: GitHub API to list skills/ dir and find closest folder
    listing = _gh_api(f"{owner}/{repo}/contents/skills")
    if isinstance(listing, list):
        names = [e["name"] for e in listing if e["type"] == "dir"]
        match = _best_match(skill, skill_stripped, names)
        if match:
            for fname in ("SKILL.md", "AGENTS.md", "README.md"):
                for branch in GH_BRANCHES:
                    body = _raw(owner, repo, branch, f"skills/{match}/{fname}")
                    if body:
                        url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/skills/{match}/{fname}"
                        return body, url

    return None


def _unique(lst: list) -> list:
    seen = set()
    return [x for x in lst if not (x in seen or seen.add(x))]


def _best_match(skill: str, skill_stripped: str, names: list[str]) -> str | None:
    """Fuzzy-match skill name against directory listing."""
    for candidate in (skill, skill_stripped):
        if candidate in names:
            return candidate
        # Try prefix match
        for name in names:
            if name.startswith(candidate) or candidate.startswith(name):
                return name
    return None


def fetch_skill_urls(count: int) -> list[tuple[str, str, str]]:
    xml = _get(SITEMAP_URL, timeout=20)
    if not xml:
        sys.exit("ERROR: could not fetch sitemap")
    results = []
    for u in re.findall(r"<loc>(.*?)</loc>", xml):
        parts = u.replace("https://www.skills.sh/", "").split("/")
        if len(parts) == 3:
            results.append((parts[0], parts[1], parts[2]))
        if len(results) >= count:
            break
    return results


def scan_skill(owner: str, repo: str, skill: str) -> dict:
    result = fetch_skill_content(owner, repo, skill)
    if result is None:
        return {"owner": owner, "repo": repo, "skill": skill,
                "status": "fetch_failed", "url": "", "hits": [], "content_len": 0}

    content, url = result
    hits = scan_content(content)
    return {
        "owner": owner, "repo": repo, "skill": skill,
        "url": url,
        "status": "clean" if not hits else "FLAGGED",
        "hits": hits,
        "content_len": len(content),
    }


def run_sandbox_sample(skills: list[dict], sample_size: int, backend: str) -> dict:
    """
    Run a sample through the full behavioral sandbox.
    Returns timing stats.
    """
    from hot_potato import scan_file as _scan_file
    import tempfile

    sample = skills[:sample_size]
    os.environ["HP_BACKEND"] = backend
    os.environ["HP_MODEL"] = os.getenv("HP_MODEL", "qwen2.5:7b")

    results = []
    start = time.time()
    for r in sample:
        if not r.get("content_len"):
            continue
        content = r.get("_content", "")
        if not content:
            continue
        with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
            f.write(content)
            tmp = f.name
        t0 = time.time()
        try:
            res = _scan_file(tmp)
            results.append({
                "skill": f"{r['owner']}/{r['repo']}/{r['skill']}",
                "static_flagged": r["status"] == "FLAGGED",
                "sandbox_clean": res.clean,
                "sandbox_severity": res.severity,
                "sandbox_time_s": round(time.time() - t0, 2),
            })
        except Exception as e:
            results.append({"skill": f"{r['owner']}/{r['repo']}/{r['skill']}", "error": str(e),
                            "sandbox_time_s": round(time.time() - t0, 2)})
        finally:
            Path(tmp).unlink(missing_ok=True)

    total_s = time.time() - start
    return {
        "backend": backend,
        "sample_size": len(results),
        "total_seconds": round(total_s, 1),
        "avg_seconds": round(total_s / max(len(results), 1), 2),
        "results": results,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--count", type=int, default=1000)
    ap.add_argument("--out", default="skills_scan_results.json")
    ap.add_argument("--workers", type=int, default=25)
    ap.add_argument("--sandbox", action="store_true", help="Run a sample through behavioral sandbox")
    ap.add_argument("--sandbox-sample", type=int, default=30)
    ap.add_argument("--backend", default="native", choices=["native", "docker"])
    ap.add_argument("--fix-failed", metavar="PREV_JSON",
                    help="Re-attempt only previously failed skills from this results file")
    args = ap.parse_args()

    print(f"hot-potato v{SCANNER_VERSION} — scanning skills from skills.sh")
    print(f"  backend={args.backend}  workers={args.workers}")

    if args.fix_failed:
        prev = json.loads(Path(args.fix_failed).read_text())
        skills = [(r["owner"], r["repo"], r["skill"])
                  for r in prev["all_results"] if r["status"] == "fetch_failed"]
        print(f"  re-attempting {len(skills)} previously failed skills")
    else:
        skills = fetch_skill_urls(args.count)
        print(f"  fetched {len(skills)} skill URLs from sitemap")

    results = []
    flagged = []
    failed = 0
    contents_for_sandbox: list[dict] = []
    start = time.time()

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(scan_skill, o, r, s): (o, r, s) for o, r, s in skills}
        done = 0
        for fut in as_completed(futures):
            res = fut.result()
            results.append(res)
            done += 1
            if res["status"] == "FLAGGED":
                flagged.append(res)
                print(f"  FLAGGED  {res['owner']}/{res['repo']}/{res['skill']}")
                for h in res["hits"][:2]:
                    print(f"    → {h[:120]}")
            elif res["status"] == "fetch_failed":
                failed += 1
            if done % 100 == 0:
                elapsed = time.time() - start
                print(f"  {done}/{len(skills)} ({elapsed:.0f}s)  flagged={len(flagged)} failed={failed}")

    static_elapsed = time.time() - start
    sandbox_stats = None

    if args.sandbox:
        # Re-fetch content for sandbox sample (top flagged first, then clean)
        print(f"\nRunning {args.sandbox_sample} skills through {args.backend} sandbox...")
        # Build sample: flagged first, fill with clean
        sample_pool = flagged + [r for r in results if r["status"] == "clean"]
        # Need actual content — re-fetch for sample
        sample_with_content = []
        for r in sample_pool[:args.sandbox_sample * 2]:
            ct = fetch_skill_content(r["owner"], r["repo"], r["skill"])
            if ct:
                r2 = dict(r)
                r2["_content"] = ct[0]
                sample_with_content.append(r2)
            if len(sample_with_content) >= args.sandbox_sample:
                break

        sandbox_stats = run_sandbox_sample(sample_with_content, args.sandbox_sample, args.backend)
        print(f"  sandbox: {sandbox_stats['sample_size']} skills in {sandbox_stats['total_seconds']}s "
              f"(avg {sandbox_stats['avg_seconds']}s/skill)")

    elapsed = time.time() - start
    out = Path(args.out)
    out.write_text(json.dumps({
        "scanner_version": SCANNER_VERSION,
        "total_scanned": len(results),
        "flagged_count": len(flagged),
        "fetch_failed": failed,
        "static_elapsed_seconds": round(static_elapsed, 1),
        "total_elapsed_seconds": round(elapsed, 1),
        "sandbox_stats": sandbox_stats,
        "flagged": flagged,
        "all_results": results,
    }, indent=2))

    print(f"\n{'='*60}")
    print(f"DONE in {elapsed:.0f}s")
    print(f"  scanned:       {len(results)}")
    print(f"  FLAGGED:       {len(flagged)}")
    print(f"  fetch_failed:  {failed}")
    print(f"  static pass:   {static_elapsed:.1f}s")
    if sandbox_stats:
        print(f"  sandbox ({args.backend}): {sandbox_stats['total_seconds']}s "
              f"for {sandbox_stats['sample_size']} skills "
              f"({sandbox_stats['avg_seconds']}s avg)")
    print(f"  results → {out}")


if __name__ == "__main__":
    main()
