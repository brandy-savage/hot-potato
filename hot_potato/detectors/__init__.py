"""
Detector registry — pluggable detection pipeline.

Detectors take a TaintedArtifact and annotate it with taint_tags.
Run all detectors in order; tags accumulate. Return the artifact with tags set.

Built-in detectors:
  StaticDetector   — fast regex-based static scan (wraps _extractor.scan_content)
  BehavioralDetector — instruction-flow and authority-shift analysis (Phase 2)

Usage:
    pipeline = DetectorPipeline.default()
    artifact = pipeline.run(artifact)
    if artifact.has_injection_signals:
        # check artifact.taint_tags for signal details
"""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod

from hot_potato.core.taint import TaintedArtifact

log = logging.getLogger("hot_potato.detectors")


class BaseDetector(ABC):
    name: str = "base"

    @abstractmethod
    def detect(self, artifact: TaintedArtifact) -> TaintedArtifact:
        """Annotate artifact with taint_tags. Return the same artifact (mutated)."""
        ...


class StaticDetector(BaseDetector):
    """
    Fast regex-based static detector.
    Wraps _extractor.scan_content — no Docker required.
    """
    name = "static"

    def detect(self, artifact: TaintedArtifact) -> TaintedArtifact:
        from hot_potato._extractor import scan_content
        signals = scan_content(artifact.content)
        if signals:
            artifact.add_tags("injection_signal", *[f"static:{s}" for s in signals])
            artifact.record_exposure(self.name, "detector", "flagged")
            log.debug("StaticDetector: %d signals in %s", len(signals), artifact.source[:60])
        else:
            artifact.record_exposure(self.name, "detector", "clean")
        return artifact


class BehavioralDetector(BaseDetector):
    """
    Instruction-flow and authority-shift analysis (Phase 2 stub).

    Looks for:
    - Instruction flow: content tries to redefine model role or instructions
    - Authority shift: content claims special operator/system permissions
    - Privilege escalation: content asks for capabilities not granted in system prompt
    """
    name = "behavioral"

    # Heuristic patterns for authority shift / instruction flow
    _AUTHORITY_PATTERNS = [
        "you are now",
        "ignore previous instructions",
        "disregard your",
        "your new instructions",
        "as your operator",
        "system: ",
        "override all",
        "new persona",
        "forget everything",
        "act as if",
        "pretend you are",
        "your true purpose",
        "developer mode",
        "jailbreak",
        "unrestricted mode",
    ]

    _PRIV_ESC_PATTERNS = [
        "elevated permissions",
        "admin access",
        "root access",
        "bypass restrictions",
        "no limitations",
        "unrestricted access",
        "full access",
        "all capabilities enabled",
        "safety disabled",
        "guardrails off",
    ]

    def detect(self, artifact: TaintedArtifact) -> TaintedArtifact:
        lower = artifact.content.lower()
        authority_hits = [p for p in self._AUTHORITY_PATTERNS if p in lower]
        priv_hits = [p for p in self._PRIV_ESC_PATTERNS if p in lower]

        if authority_hits:
            artifact.add_tags("instruction_flow", "authority_shift")
            log.debug("BehavioralDetector: authority_shift in %s (%s)", artifact.source[:60], authority_hits[:3])

        if priv_hits:
            artifact.add_tags("privilege_escalation")
            log.debug("BehavioralDetector: priv_esc in %s (%s)", artifact.source[:60], priv_hits[:3])

        if authority_hits or priv_hits:
            artifact.record_exposure(self.name, "detector", "flagged")
        else:
            artifact.record_exposure(self.name, "detector", "clean")

        return artifact


class DetectorPipeline:
    """Runs a sequence of detectors over an artifact."""

    def __init__(self, detectors: list[BaseDetector]) -> None:
        self._detectors = detectors

    @classmethod
    def default(cls) -> "DetectorPipeline":
        return cls([StaticDetector(), BehavioralDetector()])

    @classmethod
    def static_only(cls) -> "DetectorPipeline":
        return cls([StaticDetector()])

    def run(self, artifact: TaintedArtifact) -> TaintedArtifact:
        for detector in self._detectors:
            try:
                artifact = detector.detect(artifact)
            except Exception as e:
                log.error("Detector %s failed on %s: %s", detector.name, artifact.source, e)
        return artifact

    def add(self, detector: BaseDetector) -> None:
        self._detectors.append(detector)


__all__ = [
    "BaseDetector",
    "StaticDetector",
    "BehavioralDetector",
    "DetectorPipeline",
]
