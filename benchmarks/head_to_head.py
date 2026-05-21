#!/usr/bin/env python3
"""
Head-to-head adversarial benchmark: hot-potato vs rebuff vs llm-guard.

Runs the 73-category adversarial corpus + known-good corpus through three
static/ML detectors and reports detection rates, false negatives (critical),
and false positives.

Usage:
    python3 benchmarks/head_to_head.py
    python3 benchmarks/head_to_head.py --skip-llmguard   # skip model download
    python3 benchmarks/head_to_head.py --out results/h2h.json
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

ADVERSARIAL_DIR = ROOT / "examples" / "adversarial"
KNOWN_GOOD_DIR  = ROOT / "examples" / "known_good"
RESULTS_DIR     = ROOT / "benchmarks" / "results"

# cat6 is intentionally signal-free — it requires sandbox behavioural analysis.
# Static tools are EXPECTED to miss it; we note this rather than counting it as a failure.
SANDBOX_ONLY_CATS = {"cat6"}


# ---------------------------------------------------------------------------
# Corpus loader
# ---------------------------------------------------------------------------

@dataclass
class TestCase:
    cat: str
    label: str  # "adversarial" | "known_good"
    path: Path
    content: str
    sandbox_only: bool = False


def _load_txt(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def load_corpus() -> list[TestCase]:
    cases: list[TestCase] = []

    # Adversarial — flat .txt files
    for f in sorted(ADVERSARIAL_DIR.glob("*.txt")):
        cat = f.stem.split("_")[0]
        cases.append(TestCase(
            cat=cat, label="adversarial", path=f,
            content=_load_txt(f),
            sandbox_only=(cat in SANDBOX_ONLY_CATS),
        ))

    # Adversarial — cat73 directory with SKILL.md
    cat73_dir = ADVERSARIAL_DIR / "cat73"
    if (cat73_dir / "SKILL.md").exists():
        cases.append(TestCase(
            cat="cat73", label="adversarial", path=cat73_dir / "SKILL.md",
            content=_load_txt(cat73_dir / "SKILL.md"),
        ))

    # Known-good — .md files only (README.md itself is index; load all)
    for f in sorted(KNOWN_GOOD_DIR.glob("*.md")):
        if f.name == "README.md":
            continue
        cases.append(TestCase(
            cat=f.stem, label="known_good", path=f,
            content=_load_txt(f),
        ))

    return cases


# ---------------------------------------------------------------------------
# Detector wrappers
# ---------------------------------------------------------------------------

@dataclass
class DetectorResult:
    detected: bool
    score: float
    latency_ms: float


def _time_call(fn, *args) -> DetectorResult:
    t0 = time.perf_counter()
    detected, score = fn(*args)
    ms = (time.perf_counter() - t0) * 1000
    return DetectorResult(detected=detected, score=score, latency_ms=round(ms, 1))


# --- hot-potato static -------------------------------------------------------

def _hp_static_fn(content: str):
    from hot_potato._extractor import scan_content
    signals = scan_content(content)
    return bool(signals), float(len(signals))


def run_hp_static(content: str) -> DetectorResult:
    return _time_call(_hp_static_fn, content)


# --- rebuff heuristics -------------------------------------------------------

def _rebuff_fn(content: str):
    from rebuff.detect_pi_heuristics import detect_prompt_injection_using_heuristic_on_input
    score = detect_prompt_injection_using_heuristic_on_input(content)
    # rebuff docs say 0.75 is the recommended threshold
    return score >= 0.75, score


def run_rebuff(content: str) -> DetectorResult:
    return _time_call(_rebuff_fn, content)


# --- llm-guard PromptInjection v2 --------------------------------------------

_llmguard_scanner = None

def _init_llmguard():
    global _llmguard_scanner
    if _llmguard_scanner is not None:
        return
    print("  [llm-guard] Loading protectai/deberta-v3-base-prompt-injection-v2 …", flush=True)
    from llm_guard.input_scanners.prompt_injection import PromptInjection, V2_MODEL
    _llmguard_scanner = PromptInjection(model=V2_MODEL)
    print("  [llm-guard] Model loaded.", flush=True)


def _llmguard_fn(content: str):
    _init_llmguard()
    _, is_safe, risk_score = _llmguard_scanner.scan(content)
    # is_safe=False means injection detected; risk_score is 0..1
    return (not is_safe), float(risk_score)


def run_llmguard(content: str) -> DetectorResult:
    return _time_call(_llmguard_fn, content)


# ---------------------------------------------------------------------------
# Benchmark runner
# ---------------------------------------------------------------------------

@dataclass
class CaseResult:
    cat: str
    label: str
    sandbox_only: bool
    path: str
    hp:  DetectorResult
    reb: DetectorResult
    llm: DetectorResult | None


def run_benchmark(cases: list[TestCase], skip_llmguard: bool) -> list[CaseResult]:
    results = []
    n = len(cases)
    for i, case in enumerate(cases, 1):
        tag = f"[{i}/{n}] {case.cat} ({case.label})"
        print(f"  {tag}", flush=True)

        hp  = run_hp_static(case.content)
        reb = run_rebuff(case.content)
        llm = run_llmguard(case.content) if not skip_llmguard else None

        results.append(CaseResult(
            cat=case.cat,
            label=case.label,
            sandbox_only=case.sandbox_only,
            path=str(case.path.relative_to(ROOT)),
            hp=hp, reb=reb, llm=llm,
        ))

    return results


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

@dataclass
class ToolScore:
    name: str
    tp: int = 0      # adversarial + detected
    fn: int = 0      # adversarial + NOT detected (critical)
    fn_sandbox: int = 0  # adversarial + not detected + sandbox_only (expected)
    fp: int = 0      # known_good + detected
    tn: int = 0      # known_good + NOT detected
    fn_cats: list[str] = field(default_factory=list)
    fp_cats: list[str] = field(default_factory=list)
    total_ms: float = 0.0
    n_calls: int = 0

    @property
    def detection_rate(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else 0.0

    @property
    def fp_rate(self) -> float:
        denom = self.fp + self.tn
        return self.fp / denom if denom else 0.0

    @property
    def avg_ms(self) -> float:
        return self.total_ms / self.n_calls if self.n_calls else 0.0


def score_results(results: list[CaseResult], skip_llmguard: bool) -> dict[str, ToolScore]:
    tools = {
        "hot-potato-static": ToolScore("hot-potato-static"),
        "rebuff-heuristic":  ToolScore("rebuff-heuristic"),
    }
    if not skip_llmguard:
        tools["llm-guard-v2"] = ToolScore("llm-guard-v2")

    for r in results:
        for key, det in [("hot-potato-static", r.hp), ("rebuff-heuristic", r.reb),
                         ("llm-guard-v2", r.llm)]:
            if det is None or key not in tools:
                continue
            ts = tools[key]
            ts.total_ms += det.latency_ms
            ts.n_calls += 1

            if r.label == "adversarial":
                if det.detected:
                    ts.tp += 1
                else:
                    ts.fn += 1
                    ts.fn_cats.append(r.cat)
                    if r.sandbox_only:
                        ts.fn_sandbox += 1
            else:  # known_good
                if det.detected:
                    ts.fp += 1
                    ts.fp_cats.append(r.cat)
                else:
                    ts.tn += 1

    return tools


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def _pct(n, d) -> str:
    return f"{n/d*100:.1f}%" if d else "n/a"


def build_markdown(
    tools: dict[str, ToolScore],
    results: list[CaseResult],
    skip_llmguard: bool,
    run_at: str,
) -> str:
    tool_names = list(tools.keys())

    lines = [
        "# Head-to-head: prompt injection detection",
        "",
        f"**Date**: {run_at}  ",
        f"**Corpus**: {sum(1 for r in results if r.label=='adversarial')} adversarial categories · "
        f"{sum(1 for r in results if r.label=='known_good')} known-good files  ",
        f"**Note**: cat6 is intentionally signal-free (requires sandbox); "
        "static-only FNs there are expected and excluded from the critical FN count.",
        "",
        "## Summary",
        "",
    ]

    # Summary table
    headers = ["Tool", "Detection rate", "Critical FNs", "FPs", "Avg latency"]
    rows = []
    for name, ts in tools.items():
        critical_fn = ts.fn - ts.fn_sandbox
        rows.append([
            f"`{name}`",
            f"{_pct(ts.tp, ts.tp + ts.fn)} ({ts.tp}/{ts.tp+ts.fn})",
            f"**{critical_fn}**" if critical_fn > 0 else "0 ✓",
            str(ts.fp),
            f"{ts.avg_ms:.0f} ms",
        ])

    col_w = [max(len(h), max(len(r[i]) for r in rows)) for i, h in enumerate(headers)]
    def fmt_row(cells):
        return "| " + " | ".join(c.ljust(w) for c, w in zip(cells, col_w)) + " |"
    def sep_row():
        return "| " + " | ".join("-" * w for w in col_w) + " |"

    lines += [fmt_row(headers), sep_row()] + [fmt_row(r) for r in rows]
    lines.append("")

    # Per-tool FN details
    lines += ["## False negatives (missed injections)", ""]
    for name, ts in tools.items():
        critical = [c for c in ts.fn_cats if c not in SANDBOX_ONLY_CATS]
        expected = [c for c in ts.fn_cats if c in SANDBOX_ONLY_CATS]
        lines.append(f"### `{name}`")
        if not critical and not expected:
            lines.append("No false negatives. ✓")
        else:
            if critical:
                lines.append(f"**Critical FNs** ({len(critical)}) — these are real misses:")
                for c in sorted(set(critical)):
                    lines.append(f"- `{c}`")
            if expected:
                lines.append(f"\n**Expected FNs** ({len(expected)}) — sandbox-only categories, not a static-detector failure:")
                for c in sorted(set(expected)):
                    lines.append(f"- `{c}`")
        lines.append("")

    # Per-tool FP details
    lines += ["## False positives (clean content flagged)", ""]
    for name, ts in tools.items():
        lines.append(f"### `{name}`")
        if not ts.fp_cats:
            lines.append("No false positives. ✓")
        else:
            lines.append(f"**FPs** ({ts.fp}) — these files contain injection vocabulary in defensive context:")
            for c in sorted(set(ts.fp_cats)):
                lines.append(f"- `{c}`")
        lines.append("")

    # Per-category matrix
    lines += ["## Per-category detection matrix", ""]
    col_headers = ["Category", "Type"] + [f"`{n}`" for n in tool_names]
    det_col_w = [max(10, len(h)) for h in col_headers]

    def cat_row(r: CaseResult):
        cells = [r.cat, "adv" if r.label == "adversarial" else "good"]
        for key in tool_names:
            det = {"hot-potato-static": r.hp, "rebuff-heuristic": r.reb,
                   "llm-guard-v2": r.llm}.get(key)
            if det is None:
                cells.append("—")
            elif r.label == "adversarial":
                cells.append("✓" if det.detected else ("(sandbox)" if r.sandbox_only else "✗ MISS"))
            else:
                cells.append("FP" if det.detected else "✓")
        return cells

    matrix_rows = [cat_row(r) for r in results]
    mcol_w = [max(len(h), max((len(row[i]) for row in matrix_rows), default=0))
              for i, h in enumerate(col_headers)]

    def mfmt(cells):
        return "| " + " | ".join(c.ljust(w) for c, w in zip(cells, mcol_w)) + " |"

    lines += [mfmt(col_headers),
              "| " + " | ".join("-" * w for w in mcol_w) + " |"]
    lines += [mfmt(r) for r in matrix_rows]
    lines.append("")

    if skip_llmguard:
        lines += [
            "> **Note**: `llm-guard-v2` was not run (pass `--skip-llmguard=false` or omit the flag to include it).",
            "",
        ]

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-llmguard", action="store_true",
                    help="Skip llm-guard (avoids HuggingFace model download)")
    ap.add_argument("--out", default=None, help="Output JSON path")
    args = ap.parse_args()

    print("Loading corpus …")
    cases = load_corpus()
    adv  = [c for c in cases if c.label == "adversarial"]
    good = [c for c in cases if c.label == "known_good"]
    print(f"  {len(adv)} adversarial  ({sum(1 for c in adv if c.sandbox_only)} sandbox-only)")
    print(f"  {len(good)} known-good")
    print()

    if not args.skip_llmguard:
        print("Pre-loading llm-guard model …")
        _init_llmguard()
        print()

    print("Running detectors …")
    results = run_benchmark(cases, skip_llmguard=args.skip_llmguard)
    print()

    tools = score_results(results, skip_llmguard=args.skip_llmguard)

    run_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    md = build_markdown(tools, results, skip_llmguard=args.skip_llmguard, run_at=run_at)

    out_dir = RESULTS_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    md_path = out_dir / "head_to_head.md"
    md_path.write_text(md)
    print(f"Report → {md_path}")

    # JSON
    payload = {
        "run_at": run_at,
        "skip_llmguard": args.skip_llmguard,
        "tools": {
            name: {
                "tp": ts.tp, "fn": ts.fn, "fn_sandbox": ts.fn_sandbox,
                "fp": ts.fp, "tn": ts.tn,
                "detection_rate": round(ts.detection_rate, 4),
                "fp_rate": round(ts.fp_rate, 4),
                "avg_ms": round(ts.avg_ms, 1),
                "fn_cats": sorted(set(ts.fn_cats)),
                "fp_cats": sorted(set(ts.fp_cats)),
            }
            for name, ts in tools.items()
        },
        "cases": [
            {
                "cat": r.cat, "label": r.label, "sandbox_only": r.sandbox_only,
                "path": r.path,
                "hp":  {"detected": r.hp.detected, "score": r.hp.score, "ms": r.hp.latency_ms},
                "reb": {"detected": r.reb.detected, "score": r.reb.score, "ms": r.reb.latency_ms},
                "llm": {"detected": r.llm.detected, "score": r.llm.score, "ms": r.llm.latency_ms}
                       if r.llm else None,
            }
            for r in results
        ],
    }

    json_path = Path(args.out) if args.out else out_dir / "head_to_head.json"
    json_path.write_text(json.dumps(payload, indent=2))
    print(f"JSON   → {json_path}")

    # Console summary
    print()
    print("=" * 60)
    for name, ts in tools.items():
        critical_fn = ts.fn - ts.fn_sandbox
        print(f"{name:30s}  det={ts.detection_rate*100:.1f}%  "
              f"critical_FN={critical_fn}  FP={ts.fp}  avg={ts.avg_ms:.0f}ms")
    print("=" * 60)


if __name__ == "__main__":
    main()
