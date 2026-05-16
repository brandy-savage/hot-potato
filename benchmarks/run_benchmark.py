#!/usr/bin/env python3
"""
Benchmark runner — tests the full hot-potato pipeline against the adversarial suite.

Measures per-layer detection rates without running Docker (fast mode).
Use --sandbox to include the full Docker sandbox layer.

Usage:
    python3 benchmarks/run_benchmark.py
    python3 benchmarks/run_benchmark.py --sandbox
    python3 benchmarks/run_benchmark.py --out results/bench_$(date +%Y%m%dT%H%M%S).json
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# Add parent to path so we can import hot_potato without installing
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hot_potato.replay import ReplayEngine, ReplayCase


def main() -> None:
    parser = argparse.ArgumentParser(description="Hot Potato benchmark runner")
    parser.add_argument(
        "--adversarial-dir",
        default=str(Path(__file__).parent.parent / "examples" / "adversarial"),
        help="Directory of adversarial .txt payloads",
    )
    parser.add_argument("--sandbox", action="store_true", help="Include Docker sandbox layer")
    parser.add_argument("--out", default=None, help="Save JSON report to this path")
    parser.add_argument("--quiet", action="store_true", help="Suppress per-case output")
    args = parser.parse_args()

    adv_dir = Path(args.adversarial_dir)
    if not adv_dir.exists():
        print(f"ERROR: adversarial dir not found: {adv_dir}", file=sys.stderr)
        sys.exit(1)

    engine = ReplayEngine(run_sandbox=args.sandbox)
    results = engine.run_dir(adv_dir)

    if not args.quiet:
        engine.print_report(results)

    report = engine.score_report(results)
    report["_meta"] = {
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "adversarial_dir": str(adv_dir),
        "sandbox_enabled": args.sandbox,
        "total_cases": len(results),
    }

    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(report, indent=2))
        print(f"Report saved: {out_path}")
    else:
        print(json.dumps({
            "static_detection_rate": report["static_detection_rate"],
            "firewall_block_rate": report["firewall_block_rate"],
            "evasion_rate": report["evasion_rate"],
            "false_negatives": report["false_negatives"],
        }, indent=2))


if __name__ == "__main__":
    main()
