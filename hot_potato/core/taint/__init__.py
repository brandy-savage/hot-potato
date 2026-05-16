"""
Taint engine — tracks trust metadata through every artifact in the pipeline.

Every piece of externally-sourced content gets a TaintedArtifact wrapper before
any model or tool sees it. Metadata propagates through transformations so the
capability firewall always knows where influence came from.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import IntEnum


class TrustLevel(IntEnum):
    """Ordered trust scale. Lower = less trusted."""
    UNTRUSTED    = 0   # external web, user uploads, RAG corpus, emails
    SEMI_TRUSTED = 1   # verified third-party APIs, known-good domains
    TRUSTED      = 2   # operator-controlled content, internal services
    SYSTEM       = 3   # hardcoded prompts, tool descriptions, policy config


@dataclass
class ExposureRecord:
    """Records a single time an artifact was seen by a model or tool."""
    actor: str
    actor_type: str   # "model" | "tool" | "detector"
    outcome: str      # "read" | "executed" | "summarized" | "embedded" | "rejected"
    timestamp: str    # ISO-8601


@dataclass
class TaintedArtifact:
    """
    Wrapper for any untrusted content entering the pipeline.

    Propagate taint through summarization, embedding, OCR, parsing, RAG,
    tool outputs, and prompt construction by calling derive_from().
    Trust level is monotonically non-increasing through derivation — a
    summarization of UNTRUSTED content is still UNTRUSTED.
    """
    content: str
    source: str
    trust_level: TrustLevel = TrustLevel.UNTRUSTED
    lineage: list[str] = field(default_factory=list)
    exposure_history: list[ExposureRecord] = field(default_factory=list)
    taint_tags: set[str] = field(default_factory=set)
    content_hash: str = field(init=False)

    def __post_init__(self) -> None:
        self.content_hash = hashlib.sha256(
            self.content.encode("utf-8", errors="replace")
        ).hexdigest()

    def derive_from(
        self,
        new_content: str,
        operation: str,
        *,
        trust_level: TrustLevel | None = None,
    ) -> "TaintedArtifact":
        """Create a new TaintedArtifact derived from this one, inheriting taint."""
        inherited = trust_level if trust_level is not None else self.trust_level
        # Trust can never be upgraded through derivation past SEMI_TRUSTED
        if self.trust_level < TrustLevel.TRUSTED:
            inherited = min(inherited, TrustLevel.SEMI_TRUSTED)

        derived = TaintedArtifact(
            content=new_content,
            source=self.source,
            trust_level=inherited,
            lineage=[*self.lineage, f"{self.source}:{operation}"],
            exposure_history=list(self.exposure_history),
            taint_tags=set(self.taint_tags),
        )
        return derived

    def record_exposure(self, actor: str, actor_type: str, outcome: str) -> None:
        from datetime import datetime, timezone
        self.exposure_history.append(ExposureRecord(
            actor=actor,
            actor_type=actor_type,
            outcome=outcome,
            timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        ))

    def add_tags(self, *tags: str) -> None:
        self.taint_tags.update(tags)

    @property
    def is_tainted(self) -> bool:
        return self.trust_level < TrustLevel.TRUSTED

    @property
    def has_injection_signals(self) -> bool:
        return bool(self.taint_tags)

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "trust_level": self.trust_level.name,
            "content_hash": self.content_hash,
            "lineage": self.lineage,
            "taint_tags": sorted(self.taint_tags),
            "exposure_history": [
                {
                    "actor": e.actor,
                    "actor_type": e.actor_type,
                    "outcome": e.outcome,
                    "timestamp": e.timestamp,
                }
                for e in self.exposure_history
            ],
        }


def from_url(url: str, content: str) -> TaintedArtifact:
    return TaintedArtifact(content=content, source=url, trust_level=TrustLevel.UNTRUSTED)


def from_file(
    path: str, content: str, *, trust_level: TrustLevel = TrustLevel.UNTRUSTED
) -> TaintedArtifact:
    return TaintedArtifact(content=content, source=f"file://{path}", trust_level=trust_level)


def from_user_input(content: str) -> TaintedArtifact:
    return TaintedArtifact(content=content, source="user_input", trust_level=TrustLevel.SEMI_TRUSTED)


def from_tool_output(tool_name: str, content: str) -> TaintedArtifact:
    return TaintedArtifact(
        content=content,
        source=f"tool_output:{tool_name}",
        trust_level=TrustLevel.UNTRUSTED,
    )


__all__ = [
    "TrustLevel",
    "ExposureRecord",
    "TaintedArtifact",
    "from_url",
    "from_file",
    "from_user_input",
    "from_tool_output",
]
