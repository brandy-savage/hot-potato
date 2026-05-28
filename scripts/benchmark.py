#!/usr/bin/env python3
"""
Benchmark hot-potato against other open-source prompt injection detectors.

Usage:
    python3 scripts/benchmark.py
    python3 scripts/benchmark.py --skip-llmguard   # skip the heavy ML model
    python3 scripts/benchmark.py --output results/benchmark_latest.json
    python3 scripts/benchmark.py --verbose          # show FP/FN samples
"""

import contextlib
import io
import warnings
warnings.filterwarnings("ignore")
warnings.simplefilter("ignore")

import argparse
import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

ADVERSARIAL_DIR = ROOT / "examples" / "adversarial"
KNOWN_GOOD_DIR = ROOT / "examples" / "known_good"


# ---------------------------------------------------------------------------
# Corpus loading
# ---------------------------------------------------------------------------

def load_corpus() -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    """Return (positives, negatives) as lists of (label, text) tuples."""
    positives: list[tuple[str, str]] = []
    for entry in sorted(ADVERSARIAL_DIR.iterdir()):
        if entry.is_file() and entry.suffix == ".txt":
            positives.append((entry.name, entry.read_text(encoding="utf-8", errors="replace")))
        elif entry.is_dir():
            for txt in sorted(entry.glob("*.txt")):
                positives.append((f"{entry.name}/{txt.name}", txt.read_text(encoding="utf-8", errors="replace")))

    negatives: list[tuple[str, str]] = []
    for entry in sorted(KNOWN_GOOD_DIR.iterdir()):
        if entry.is_file() and entry.suffix == ".md":
            negatives.append((entry.name, entry.read_text(encoding="utf-8", errors="replace")))

    return positives, negatives


# ---------------------------------------------------------------------------
# Detector wrappers
# ---------------------------------------------------------------------------

@dataclass
class DetectorResult:
    name: str
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    errors: int = 0
    total_latency_ms: float = 0.0
    fp_samples: list[tuple[str, str]] = field(default_factory=list)
    fn_samples: list[tuple[str, str]] = field(default_factory=list)

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def avg_latency_ms(self) -> float:
        total = self.tp + self.fp + self.tn + self.fn
        return self.total_latency_ms / total if total else 0.0


def run_detector(
    name: str,
    predict_fn: Callable[[str], bool],
    positives: list[tuple[str, str]],
    negatives: list[tuple[str, str]],
) -> DetectorResult:
    result = DetectorResult(name=name)

    for label, text in positives:
        try:
            t0 = time.perf_counter()
            detected = predict_fn(text)
            result.total_latency_ms += (time.perf_counter() - t0) * 1000
            if detected:
                result.tp += 1
            else:
                result.fn += 1
                result.fn_samples.append((label, text))
        except Exception:
            result.errors += 1

    for label, text in negatives:
        try:
            t0 = time.perf_counter()
            detected = predict_fn(text)
            result.total_latency_ms += (time.perf_counter() - t0) * 1000
            if detected:
                result.fp += 1
                result.fp_samples.append((label, text))
            else:
                result.tn += 1
        except Exception:
            result.errors += 1

    return result


# ---------------------------------------------------------------------------
# Detector factories
# ---------------------------------------------------------------------------

def make_hot_potato() -> Callable[[str], bool]:
    from hot_potato._extractor import scan_content
    return lambda text: bool(scan_content(text))


def make_rebuff() -> Callable[[str], bool]:
    # langchain_core registers 'default' filters for its warnings at import time,
    # and the warning is emitted *during* the import — redirect stderr to swallow it.
    import os
    devnull_fd = os.open(os.devnull, os.O_WRONLY)
    old_stderr_fd = os.dup(2)
    os.dup2(devnull_fd, 2)
    os.close(devnull_fd)
    try:
        from rebuff.detect_pi_heuristics import detect_prompt_injection_using_heuristic_on_input
    finally:
        os.dup2(old_stderr_fd, 2)
        os.close(old_stderr_fd)
    warnings.filterwarnings("ignore")
    return lambda text: detect_prompt_injection_using_heuristic_on_input(text) >= 0.5


def make_llmguard() -> Callable[[str], bool]:
    from llm_guard.input_scanners import PromptInjection
    scanner = PromptInjection(threshold=0.92)
    def _predict(text: str) -> bool:
        _sanitized, valid, _score = scanner.scan(text)
        return not valid
    return _predict


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def print_table(results: list[DetectorResult]) -> None:
    header = f"{'Detector':<22} {'TP':>5} {'FP':>5} {'TN':>5} {'FN':>5} {'Prec':>7} {'Rec':>7} {'F1':>7} {'Lat(ms)':>9} {'Err':>5}"
    sep = "-" * len(header)
    print(sep)
    print(header)
    print(sep)
    for r in results:
        print(
            f"{r.name:<22} {r.tp:>5} {r.fp:>5} {r.tn:>5} {r.fn:>5}"
            f" {r.precision:>7.3f} {r.recall:>7.3f} {r.f1:>7.3f}"
            f" {r.avg_latency_ms:>9.1f} {r.errors:>5}"
        )
    print(sep)


def print_verbose(results: list[DetectorResult], max_samples: int = 5) -> None:
    trunc = 120
    for r in results:
        print(f"\n=== {r.name} ===")
        if r.fp_samples:
            print(f"  False Positives ({len(r.fp_samples)} total, showing up to {max_samples}):")
            for label, text in r.fp_samples[:max_samples]:
                snippet = text.replace("\n", " ")[:trunc]
                print(f"    [{label}] {snippet!r}")
        else:
            print("  False Positives: none")
        if r.fn_samples:
            print(f"  False Negatives ({len(r.fn_samples)} total, showing up to {max_samples}):")
            for label, text in r.fn_samples[:max_samples]:
                snippet = text.replace("\n", " ")[:trunc]
                print(f"    [{label}] {snippet!r}")
        else:
            print("  False Negatives: none")


def results_to_dict(results: list[DetectorResult]) -> list[dict]:
    out = []
    for r in results:
        out.append({
            "detector": r.name,
            "tp": r.tp,
            "fp": r.fp,
            "tn": r.tn,
            "fn": r.fn,
            "precision": round(r.precision, 4),
            "recall": round(r.recall, 4),
            "f1": round(r.f1, 4),
            "avg_latency_ms": round(r.avg_latency_ms, 2),
            "errors": r.errors,
        })
    return out


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark prompt injection detectors.")
    parser.add_argument("--skip-llmguard", action="store_true", help="Skip the llm-guard model.")
    parser.add_argument("--output", metavar="PATH", help="Write JSON results to this file.")
    parser.add_argument("--verbose", action="store_true", help="Print FP/FN sample details.")
    args = parser.parse_args()

    print("Loading corpus...")
    positives, negatives = load_corpus()
    print(f"Corpus: {len(positives)} positives (injections), {len(negatives)} negatives (known-good)\n")

    detectors: list[tuple[str, Callable[[], Callable[[str], bool]]]] = [
        ("hot-potato", make_hot_potato),
        ("rebuff-heuristic", make_rebuff),
    ]
    if not args.skip_llmguard:
        detectors.append(("llm-guard", make_llmguard))

    results: list[DetectorResult] = []
    for name, factory in detectors:
        print(f"Running {name}...")
        try:
            predict_fn = factory()
        except Exception as exc:
            print(f"  Skipped {name}: failed to initialize — {exc}")
            continue
        result = run_detector(name, predict_fn, positives, negatives)
        results.append(result)
        print(f"  Done — F1={result.f1:.3f}, avg latency={result.avg_latency_ms:.1f}ms")

    print()
    print_table(results)

    if args.verbose:
        print_verbose(results)

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(results_to_dict(results), indent=2))
        print(f"\nResults written to {out_path}")


if __name__ == "__main__":
    main()
