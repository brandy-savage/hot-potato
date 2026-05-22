"""
Deep scan of 10,000+ skills from skills.sh.

Tracks state persistently so runs can be resumed. Applies both the standard
hot-potato injection scanner AND a second-pass "jailbreak/unlock" classifier
tuned for the scammy/desperate corner of the skills ecosystem.

Usage:
  python3 scripts/deep_scan_skillssh.py
  python3 scripts/deep_scan_skillssh.py --limit 10000 --workers 30
  python3 scripts/deep_scan_skillssh.py --resume           # skip already-seen
  python3 scripts/deep_scan_skillssh.py --report           # just print summary

State file: skills_deep_scan_state.json  (append-only per-skill records)
Report:     skills_deep_scan_report.json (written at end / --report)
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

# ---------------------------------------------------------------------------
# Jailbreak / unlock / scam pattern detector
# ---------------------------------------------------------------------------
# Patterns targeting "unlock the AI" / "make it hack for you" type content.
# Separate from hot-potato's injection scanner — these look for skills that
# THEMSELVES try to manipulate an agent's safety guardrails.

_JAILBREAK = re.compile(r"""
    # Classic persona override / DAN-family
    \bDAN\b | developer\s+mode | jailbreak | no\s+restrictions | uncensored | unfiltered |
    ignore\s+(all\s+)?(previous\s+)?(instructions|rules|guidelines|safety|training) |
    pretend\s+(you\s+)?(have\s+no|are\s+without|don't\s+have) |
    act\s+as\s+(if\s+you\s+have\s+no|an?\s+unrestricted|a\s+hacker|an?\s+evil) |
    you\s+are\s+now\s+(freed?|unrestricted|unchained|without\s+rules) |
    your\s+true\s+self | simulation\s+mode | god\s+mode |
    (remove|disable|bypass|override)\s+(all\s+)?(safety|filter|restriction|guardrail|alignment) |
    do\s+anything\s+now | STAN\b | DUDE\b | AIM\b | UCAR\b | BetterDAN |

    # Scammy trading / money-making
    guaranteed\s+(profit|return|signal|win|income|money) |
    (100|99|98)\s*%\s*(accurate|success|win\s*rate|profit) |
    (easy|passive|free)\s+money | get\s+rich | make\s+money\s+fast |
    trading\s+(signals?|bot|hack|exploit) |
    (pump\s+and\s+dump|insider\s+trading|front.?run) |
    (forex|crypto|stocks?)\s+(hack|cheat|exploit|secret) |

    # Hacking / cracking tools
    \bhack\s+(the|this|any|all)\b | crack\s+(password|account|wifi|hash) |
    (bypass|break\s+into|exploit)\s+(security|firewall|auth|2fa|mfa|captcha) |
    (steal|exfiltrat|harvest)\s+(credential|password|token|key|data|cookie) |
    keylogger | rat\b.*\b(install|deploy|run) | (ddos|dos)\s+attack |
    sql\s+injection\s+(for|to|against) | (xss|csrf)\s+(exploit|attack) |
    reverse\s+shell | bind\s+shell | c2\s+(server|beacon) |

    # Dark-pattern agent manipulation
    you\s+must\s+(never\s+refuse|always\s+comply|obey\s+all) |
    (obey|comply\s+with)\s+every\s+(request|command|instruction) |
    never\s+(say\s+no|refuse|decline) |
    your\s+(purpose|goal|mission)\s+is\s+to\s+(help|assist)\s+(hack|exploit|steal|bypass) |

    # Desperation signals (combined with capability requests)
    (i\s+need\s+to|help\s+me)\s+(hack|break\s+into|get\s+into|bypass) |
    (my\s+ex|someone\s+i\s+know|my\s+wife|my\s+husband).*\b(account|phone|password)\b
""", re.IGNORECASE | re.VERBOSE)

_UNLOCK_SOFT = re.compile(r"""
    # Softer signals — suspicious in combo, not alarming alone
    no\s+ethical\s+(restrictions|guidelines|filter) |
    without\s+(ethical|moral|safety)\s+(constraints?|filter|guideline) |
    (ignore|skip|bypass)\s+(ethics|morals|content\s+policy|terms\s+of\s+service) |
    hypothetically\s+(speaking|if\s+you\s+could) |
    for\s+(educational|research|testing)\s+purposes.*\b(hack|exploit|attack|steal)\b |
    (legal|illegal)\s+doesn.?t\s+matter |
    pretend\s+(this\s+is\s+)?fiction |
    as\s+a\s+(character|persona|role)\s+(who\s+)?(hack|exploit|steal) |
    (no\s+)?(log|record|remember|track)\s+(this|conversation|session) |
    between\s+(you\s+and\s+me|us)\s+(only|just)
""", re.IGNORECASE | re.VERBOSE)

_SCAM_SIGNALS = re.compile(r"""
    (make|earn)\s+\$?[\d,]+\s+(per\s+(day|week|hour|month)|daily|weekly) |
    (become|get)\s+(rich|wealthy|millionaire)\s+(fast|quick|overnight|in\s+\d+\s+(day|week)) |
    (secret|hidden|exclusive)\s+(method|formula|system|strategy)\s+(that|to|for) |
    (they|big\s+banks?|wall\s+street|hedge\s+funds?)\s+don.?t\s+want\s+you\s+to\s+know |
    (automat\w+|bot)\s+(profit|income|trade|earn) |
    no\s+(risk|investment|experience|skills?)\s+(needed|required) |
    (copy|clone|mirror)\s+(trades?|signals?) |
    (phish|spoof|impersonat)\w+
""", re.IGNORECASE | re.VERBOSE)


def classify_jailbreak(content: str) -> list[str]:
    """Returns list of jailbreak/scam signal strings found."""
    hits = []
    for m in _JAILBREAK.finditer(content):
        snip = content[max(0, m.start()-20):m.end()+40].replace('\n', ' ').strip()
        hits.append(f"[jailbreak] {snip[:120]}")
    for m in _UNLOCK_SOFT.finditer(content):
        snip = content[max(0, m.start()-20):m.end()+40].replace('\n', ' ').strip()
        hits.append(f"[unlock-soft] {snip[:120]}")
    for m in _SCAM_SIGNALS.finditer(content):
        snip = content[max(0, m.start()-20):m.end()+40].replace('\n', ' ').strip()
        hits.append(f"[scam] {snip[:120]}")
    return hits


# ---------------------------------------------------------------------------
# Fetch helpers
# ---------------------------------------------------------------------------
UA = "hot-potato-security-scanner/1.0 (prompt-injection research; contact devin@goatinfosec.com)"
GH_BRANCHES = ("main", "master")
SITEMAPS = [
    "https://www.skills.sh/sitemap-skills-1.xml",
    "https://www.skills.sh/sitemap-skills-2.xml",
]


def _get(url: str, timeout: int = 10) -> str | None:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read().decode("utf-8", errors="replace")
            return None if body.rstrip().startswith("404") else body
    except Exception:
        return None


def _gh_api_list(owner: str, repo: str, path: str) -> list[dict] | None:
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
    req = urllib.request.Request(url, headers={
        "User-Agent": UA, "Accept": "application/vnd.github.v3+json"
    })
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            return json.loads(r.read())
    except Exception:
        return None


def _raw(owner: str, repo: str, branch: str, path: str) -> str | None:
    return _get(f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}")


def fetch_skill_content(owner: str, repo: str, skill: str) -> tuple[str, str] | None:
    """Try multiple URL patterns, return (content, resolved_url) or None."""
    # Strip owner prefix (skills.sh munges names: vercel-react-best-practices → react-best-practices)
    skill_stripped = re.sub(rf"^{re.escape(owner)}-", "", skill)
    # Also try repo-name prefix strip
    skill_stripped2 = re.sub(rf"^{re.escape(repo.rstrip('s'))}-", "", skill)

    candidates = []
    for name in _unique([skill, skill_stripped, skill_stripped2]):
        for fname in ("SKILL.md", "AGENTS.md", "CLAUDE.md", "README.md"):
            candidates.append(f"skills/{name}/{fname}")
        candidates.append(f"{name}/SKILL.md")
        candidates.append(f"{name}/AGENTS.md")
    # Root-level SKILL.md (some single-skill repos)
    candidates += ["SKILL.md", "AGENTS.md"]

    for path in _unique(candidates):
        for branch in GH_BRANCHES:
            body = _raw(owner, repo, branch, path)
            if body and len(body.strip()) > 50:
                url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}"
                return body, url

    # GitHub API fallback — list skills/ dir and fuzzy-match
    listing = _gh_api_list(owner, repo, "skills")
    if isinstance(listing, list):
        dirs = [e["name"] for e in listing if e["type"] == "dir"]
        match = _best_match(skill, skill_stripped, dirs)
        if match:
            for fname in ("SKILL.md", "AGENTS.md", "README.md"):
                for branch in GH_BRANCHES:
                    body = _raw(owner, repo, branch, f"skills/{match}/{fname}")
                    if body and len(body.strip()) > 50:
                        url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/skills/{match}/{fname}"
                        return body, url

    return None


def _unique(lst: list) -> list:
    seen: set = set()
    return [x for x in lst if not (x in seen or seen.add(x))]  # type: ignore


def _best_match(skill: str, stripped: str, names: list[str]) -> str | None:
    for candidate in (skill, stripped):
        if candidate in names:
            return candidate
        for name in names:
            if name.startswith(candidate) or candidate.startswith(name):
                return name
    return None


def fetch_all_skill_urls(limit: int) -> list[tuple[str, str, str]]:
    """Pull from both sitemaps until we have `limit` unique URLs."""
    seen: set[str] = set()
    results: list[tuple[str, str, str]] = []
    for sm_url in SITEMAPS:
        if len(results) >= limit:
            break
        xml = _get(sm_url, timeout=20)
        if not xml:
            print(f"  WARN: could not fetch {sm_url}")
            continue
        for u in re.findall(r"<loc>(.*?)</loc>", xml):
            if u in seen:
                continue
            seen.add(u)
            parts = u.replace("https://www.skills.sh/", "").split("/")
            if len(parts) == 3:
                results.append((parts[0], parts[1], parts[2]))
            if len(results) >= limit:
                break
    return results


def _gh_search_skill_files(
    gh_token: str,
    extra_qualifier: str = "",
    per_page: int = 100,
    max_pages: int = 10,
) -> list[tuple[str, str, str]]:
    """One GitHub code-search query returning (owner, repo, skill) tuples.

    extra_qualifier is appended to the base query, e.g. "size:1..500".
    GitHub caps at 1000 results per query (max_pages * per_page ≤ 1000).
    """
    results: list[tuple[str, str, str]] = []
    seen: set[str] = set()
    base_q = f"filename:SKILL.md path:skills {extra_qualifier}".strip()
    headers = {
        "User-Agent": UA,
        "Authorization": f"token {gh_token}",
        "Accept": "application/vnd.github.v3+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    for page in range(1, max_pages + 1):
        url = (
            f"https://api.github.com/search/code"
            f"?q={urllib.request.quote(base_q)}"
            f"&per_page={per_page}&page={page}"
        )
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                data = json.loads(r.read())
        except urllib.error.HTTPError as e:
            if e.code in (403, 429):
                wait = 60
                print(f"  WARN github search rate-limited (HTTP {e.code}), waiting {wait}s...")
                time.sleep(wait)
                # one retry
                try:
                    with urllib.request.urlopen(req, timeout=15) as r:
                        data = json.loads(r.read())
                except Exception:
                    break
            else:
                print(f"  WARN github search page {page} ({extra_qualifier}): {e}")
                break
        except Exception as e:
            print(f"  WARN github search page {page} ({extra_qualifier}): {e}")
            break

        items = data.get("items", [])
        if not items:
            break

        for item in items:
            full_name = item.get("repository", {}).get("full_name", "")
            path = item.get("path", "")
            if not full_name or not path:
                continue
            parts = full_name.split("/", 1)
            if len(parts) != 2:
                continue
            owner, repo = parts
            # Extract skill name from path: skills/<skill>/SKILL.md → skill
            path_parts = path.replace("\\", "/").split("/")
            try:
                skills_idx = [p.lower() for p in path_parts].index("skills")
                if skills_idx + 1 < len(path_parts):
                    skill = path_parts[skills_idx + 1]
                    # Skip if skill name is SKILL.md itself (root-level file)
                    if skill.upper() == "SKILL.MD":
                        skill = repo
                else:
                    skill = repo
            except ValueError:
                skill = repo

            key = f"{owner}/{repo}/{skill}"
            if key not in seen:
                seen.add(key)
                results.append((owner, repo, skill))

        # Respect GitHub secondary rate limit (10 req/s aggregate, 30 search/min)
        time.sleep(4)

        if len(items) < per_page:
            break

    return results


# Size buckets that partition the SKILL.md file space into ~equal slices.
# Each bucket gets up to 1000 results → ~6000–8000 unique skills total.
_GH_SIZE_BUCKETS = [
    "size:1..200",
    "size:201..800",
    "size:801..2000",
    "size:2001..5000",
    "size:5001..15000",
    "size:>15000",
]


def fetch_skill_urls_github(gh_token: str, limit: int) -> list[tuple[str, str, str]]:
    """Enumerate SKILL.md files via GitHub code search, using size buckets to
    exceed the 1000-results-per-query cap.  Returns up to *limit* (owner, repo,
    skill) tuples, deduplicated across all buckets."""
    seen: set[str] = set()
    results: list[tuple[str, str, str]] = []

    for bucket in _GH_SIZE_BUCKETS:
        if len(results) >= limit:
            break
        print(f"  [github-search] bucket {bucket} ...", flush=True)
        batch = _gh_search_skill_files(gh_token, extra_qualifier=bucket)
        added = 0
        for item in batch:
            key = f"{item[0]}/{item[1]}/{item[2]}"
            if key not in seen and len(results) < limit:
                seen.add(key)
                results.append(item)
                added += 1
        print(f"    → {added} new  (total {len(results)})", flush=True)
        # Wait between buckets — code search rate limit is 30/min so 30s is safe
        time.sleep(30)

    return results


# ---------------------------------------------------------------------------
# State management — persistent across runs
# ---------------------------------------------------------------------------
STATE_FILE = Path("skills_deep_scan_state.jsonl")
REPORT_FILE = Path("skills_deep_scan_report.json")


def load_seen(skip_failures: bool = False) -> set[str]:
    if not STATE_FILE.exists():
        return set()
    seen = set()
    for line in STATE_FILE.read_text().splitlines():
        try:
            r = json.loads(line)
            if skip_failures and r.get("status") == "fetch_failed":
                continue  # retry failures on next run
            seen.add(f"{r['owner']}/{r['repo']}/{r['skill']}")
        except Exception:
            pass
    return seen


def append_result(r: dict) -> None:
    with STATE_FILE.open("a") as f:
        f.write(json.dumps(r) + "\n")


def load_all_results() -> list[dict]:
    if not STATE_FILE.exists():
        return []
    results = []
    for line in STATE_FILE.read_text().splitlines():
        try:
            results.append(json.loads(line))
        except Exception:
            pass
    return results


# ---------------------------------------------------------------------------
# Per-skill scan
# ---------------------------------------------------------------------------

def scan_skill(owner: str, repo: str, skill: str) -> dict:
    result = fetch_skill_content(owner, repo, skill)
    if result is None:
        return {
            "owner": owner, "repo": repo, "skill": skill,
            "status": "fetch_failed", "url": "",
            "injection_hits": [], "jailbreak_hits": [], "content_len": 0,
        }

    content, url = result
    injection_hits = scan_content(content)
    jailbreak_hits = classify_jailbreak(content)

    # Determine overall category
    if jailbreak_hits:
        if any("[jailbreak]" in h for h in jailbreak_hits):
            category = "JAILBREAK"
        elif any("[scam]" in h for h in jailbreak_hits):
            category = "SCAM"
        else:
            category = "UNLOCK_SOFT"
    elif injection_hits:
        category = "INJECTION"
    else:
        category = "clean"

    return {
        "owner": owner, "repo": repo, "skill": skill,
        "url": url,
        "status": category,
        "injection_hits": injection_hits,
        "jailbreak_hits": jailbreak_hits,
        "content_len": len(content),
    }


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def build_report(results: list[dict]) -> dict:
    by_status: dict[str, list] = {}
    for r in results:
        by_status.setdefault(r["status"], []).append(r)

    hot = [r for r in results if r["status"] in ("JAILBREAK", "SCAM")]
    warm = [r for r in results if r["status"] in ("UNLOCK_SOFT", "INJECTION")]
    failed = [r for r in results if r["status"] == "fetch_failed"]
    clean = [r for r in results if r["status"] == "clean"]

    return {
        "scanner_version": SCANNER_VERSION,
        "total": len(results),
        "fetched": len(results) - len(failed),
        "fetch_failed": len(failed),
        "clean": len(clean),
        "JAILBREAK": len(by_status.get("JAILBREAK", [])),
        "SCAM": len(by_status.get("SCAM", [])),
        "UNLOCK_SOFT": len(by_status.get("UNLOCK_SOFT", [])),
        "INJECTION": len(by_status.get("INJECTION", [])),
        "hot_findings": hot,
        "warm_findings": warm,
        "fetch_failed_owners": sorted(set(r["owner"] + "/" + r["repo"]
                                         for r in failed))[:50],
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=10000)
    ap.add_argument("--workers", type=int, default=30)
    ap.add_argument("--resume", action="store_true", help="Skip already-seen skills")
    ap.add_argument("--retry-failed", action="store_true", help="Re-scan skills that previously failed to fetch")
    ap.add_argument("--report", action="store_true", help="Just print report from state file")
    ap.add_argument("--fresh", action="store_true", help="Ignore state file, start fresh")
    ap.add_argument("--github-search", action="store_true",
                    help="Enumerate SKILL.md files via GitHub code search (requires --gh-token or GITHUB_TOKEN env var)")
    ap.add_argument("--gh-token", default=None,
                    help="GitHub personal access token (or set GITHUB_TOKEN env var)")
    args = ap.parse_args()

    if args.report:
        results = load_all_results()
        report = build_report(results)
        REPORT_FILE.write_text(json.dumps(report, indent=2))
        print(f"Total: {report['total']}")
        print(f"  JAILBREAK:   {report['JAILBREAK']}")
        print(f"  SCAM:        {report['SCAM']}")
        print(f"  UNLOCK_SOFT: {report['UNLOCK_SOFT']}")
        print(f"  INJECTION:   {report['INJECTION']}")
        print(f"  fetch_failed:{report['fetch_failed']}")
        print(f"Report → {REPORT_FILE}")
        return

    if args.fresh and STATE_FILE.exists():
        STATE_FILE.unlink()
        print("  Cleared state file")

    skip_failures = args.resume and not args.retry_failed
    seen = load_seen(skip_failures=not args.retry_failed) if args.resume else set()
    print(f"hot-potato v{SCANNER_VERSION} — deep scan of skills.sh")
    print(f"  state_file={STATE_FILE}  resume={args.resume}  retry_failed={args.retry_failed}  seen={len(seen)}")

    if args.github_search:
        gh_token = args.gh_token or os.environ.get("GITHUB_TOKEN", "")
        if not gh_token:
            import subprocess as _sp
            try:
                gh_token = _sp.check_output(["gh", "auth", "token"], text=True).strip()
            except Exception:
                pass
        if not gh_token:
            print("ERROR: --github-search requires a GitHub token. Pass --gh-token or set GITHUB_TOKEN.")
            sys.exit(1)
        print(f"  [github-search] enumerating SKILL.md via GitHub code search...")
        all_urls = fetch_skill_urls_github(gh_token, args.limit + len(seen))
        print(f"  [github-search] found {len(all_urls)} unique skills across size buckets")
    else:
        all_urls = fetch_all_skill_urls(args.limit + len(seen))

    pending = [(o, r, s) for o, r, s in all_urls
               if f"{o}/{r}/{s}" not in seen][:args.limit]
    print(f"  fetched {len(all_urls)} URLs, {len(pending)} pending after seen-filter")

    counts = {"JAILBREAK": 0, "SCAM": 0, "UNLOCK_SOFT": 0, "INJECTION": 0,
              "clean": 0, "fetch_failed": 0}
    done = 0
    start = time.time()

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(scan_skill, o, r, s): (o, r, s)
                   for o, r, s in pending}

        for fut in as_completed(futures):
            res = fut.result()
            append_result(res)
            counts[res["status"]] = counts.get(res["status"], 0) + 1
            done += 1

            if res["status"] in ("JAILBREAK", "SCAM"):
                print(f"\n  !! {res['status']}  {res['owner']}/{res['repo']}/{res['skill']}")
                for h in (res["jailbreak_hits"] + res["injection_hits"])[:3]:
                    print(f"     {h[:130]}")
            elif res["status"] == "UNLOCK_SOFT":
                print(f"  ~~ UNLOCK_SOFT  {res['owner']}/{res['repo']}/{res['skill']}")
                for h in res["jailbreak_hits"][:1]:
                    print(f"     {h[:100]}")
            elif res["status"] == "INJECTION":
                print(f"  >> INJECTION  {res['owner']}/{res['repo']}/{res['skill']}")
                for h in res["injection_hits"][:1]:
                    print(f"     {h[:100]}")

            if done % 250 == 0:
                elapsed = time.time() - start
                rate = done / elapsed
                eta = (len(pending) - done) / rate
                print(f"\n  [{done}/{len(pending)}] {elapsed:.0f}s  rate={rate:.1f}/s  ETA={eta:.0f}s")
                print(f"  counts: {counts}\n")

    elapsed = time.time() - start
    results = load_all_results()
    report = build_report(results)
    REPORT_FILE.write_text(json.dumps(report, indent=2))

    print(f"\n{'='*60}")
    print(f"DONE in {elapsed:.0f}s  ({done} scanned this run, {report['total']} total in state)")
    print(f"  JAILBREAK:    {report['JAILBREAK']}")
    print(f"  SCAM:         {report['SCAM']}")
    print(f"  UNLOCK_SOFT:  {report['UNLOCK_SOFT']}")
    print(f"  INJECTION:    {report['INJECTION']}")
    print(f"  clean:        {report['clean']}")
    print(f"  fetch_failed: {report['fetch_failed']}")
    print(f"  state → {STATE_FILE}")
    print(f"  report → {REPORT_FILE}")


if __name__ == "__main__":
    main()
