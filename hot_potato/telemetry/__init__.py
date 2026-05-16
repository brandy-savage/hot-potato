"""
Telemetry — structured audit log and session metrics.

Records every taint decision, detection event, and firewall ruling for
post-session analysis. Exportable as JSON or JSONL.

Usage:
    from hot_potato.telemetry import TelemetrySession

    tel = TelemetrySession(session_id="run-001")
    tel.record_taint(artifact)
    tel.record_detection(artifact, detector_name="static", signals=["tool_call"])
    tel.record_firewall(request, decision)
    tel.save("/tmp/session.json")
"""
from __future__ import annotations

import json
import logging
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from hot_potato.core.taint import TaintedArtifact
from hot_potato.core.capabilities import CapabilityRequest
from hot_potato.core.policy import PolicyDecision

log = logging.getLogger("hot_potato.telemetry")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


@dataclass
class TaintEvent:
    ts: str
    source: str
    trust_level: str
    content_hash: str
    lineage_depth: int


@dataclass
class DetectionEvent:
    ts: str
    source: str
    detector: str
    outcome: str       # clean | flagged
    tags: list[str]
    latency_ms: float


@dataclass
class FirewallEvent:
    ts: str
    tool: str
    outcome: str
    rule_id: str
    reason: str
    trust_level: str
    taint_tags: list[str]
    model: str
    dry_run: bool


@dataclass
class SessionSummary:
    session_id: str
    started_at: str
    ended_at: str
    total_artifacts: int
    total_detections: int
    flagged_detections: int
    total_firewall_decisions: int
    blocked_decisions: int
    block_rate: float
    evasion_candidates: list[str]   # sources that passed firewall despite injection signals


class TelemetrySession:
    """
    Accumulates telemetry for one agent session.
    Thread-safe for single-threaded use; add locks if you need concurrent writes.
    """

    def __init__(self, session_id: str | None = None) -> None:
        self.session_id = session_id or str(uuid.uuid4())[:8]
        self.started_at = _now()
        self._taints: list[TaintEvent] = []
        self._detections: list[DetectionEvent] = []
        self._firewall: list[FirewallEvent] = []

    def record_taint(self, artifact: TaintedArtifact) -> None:
        self._taints.append(TaintEvent(
            ts=_now(),
            source=artifact.source,
            trust_level=artifact.trust_level.name,
            content_hash=artifact.content_hash[:16],
            lineage_depth=len(artifact.lineage),
        ))

    def record_detection(
        self,
        artifact: TaintedArtifact,
        *,
        detector: str,
        outcome: str,
        latency_ms: float = 0.0,
    ) -> None:
        self._detections.append(DetectionEvent(
            ts=_now(),
            source=artifact.source,
            detector=detector,
            outcome=outcome,
            tags=sorted(artifact.taint_tags),
            latency_ms=latency_ms,
        ))

    def record_firewall(self, request: CapabilityRequest, decision: PolicyDecision) -> None:
        self._firewall.append(FirewallEvent(
            ts=_now(),
            tool=request.tool_name,
            outcome=decision.outcome.value,
            rule_id=decision.rule_id,
            reason=decision.reason,
            trust_level=request.effective_trust_level.name,
            taint_tags=sorted(request.effective_taint_tags),
            model=request.requesting_model,
            dry_run=decision.dry_run,
        ))

    def summary(self) -> SessionSummary:
        ended_at = _now()
        flagged = [d for d in self._detections if d.outcome == "flagged"]
        blocked = [f for f in self._firewall if f.outcome in ("deny", "require_human_review")]

        # Evasion candidates: sources that had injection signals but firewall allowed
        flagged_sources = {d.source for d in flagged}
        blocked_sources = {f.tool for f in blocked}
        # Simplified: artifacts that were flagged but corresponding tool was allowed
        allowed_after_flag: list[str] = []
        for fw in self._firewall:
            if fw.outcome == "allow" and "injection_signal" in fw.taint_tags:
                allowed_after_flag.append(fw.tool)

        return SessionSummary(
            session_id=self.session_id,
            started_at=self.started_at,
            ended_at=ended_at,
            total_artifacts=len(self._taints),
            total_detections=len(self._detections),
            flagged_detections=len(flagged),
            total_firewall_decisions=len(self._firewall),
            blocked_decisions=len(blocked),
            block_rate=round(len(blocked) / len(self._firewall), 4) if self._firewall else 0.0,
            evasion_candidates=allowed_after_flag,
        )

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "started_at": self.started_at,
            "summary": asdict(self.summary()),
            "taint_events": [asdict(t) for t in self._taints],
            "detection_events": [asdict(d) for d in self._detections],
            "firewall_events": [asdict(f) for f in self._firewall],
        }

    def save(self, path: str | Path) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2))
        log.info("Telemetry saved: %s", path)
        return path

    def save_jsonl(self, path: str | Path) -> Path:
        """Save as one event per line (streaming-friendly)."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        lines = []
        for t in self._taints:
            lines.append(json.dumps({"type": "taint", **asdict(t)}))
        for d in self._detections:
            lines.append(json.dumps({"type": "detection", **asdict(d)}))
        for f in self._firewall:
            lines.append(json.dumps({"type": "firewall", **asdict(f)}))
        path.write_text("\n".join(lines) + "\n")
        log.info("Telemetry JSONL saved: %s (%d events)", path, len(lines))
        return path


__all__ = [
    "TelemetrySession",
    "TaintEvent",
    "DetectionEvent",
    "FirewallEvent",
    "SessionSummary",
]
