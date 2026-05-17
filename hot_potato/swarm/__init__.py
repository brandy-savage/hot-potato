"""
Artifact swarm — concurrent processing queue for batches of TaintedArtifacts.

Fans artifacts out across a thread pool through the full pipeline:
  taint → detect → firewall → (optional sandbox)

Results stream back as they complete via an iterator or a blocking wait.

Usage:
    from hot_potato.swarm import ArtifactSwarm
    from hot_potato.core.taint import from_url, from_file

    swarm = ArtifactSwarm(workers=8)

    # Submit individual or batch
    swarm.submit(from_url("https://example.com", content))
    swarm.submit_many([from_file(p, p.read_text()) for p in files])

    # Stream results as they finish
    for result in swarm.as_completed():
        if result.blocked:
            print(f"BLOCKED {result.artifact.source}: {result.decision.reason}")

    # Or block until all done
    results = swarm.wait()
    print(swarm.summary(results))
"""
from __future__ import annotations

import logging
import queue
import threading
import time
import uuid
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Iterator

from hot_potato.core.taint import TaintedArtifact
from hot_potato.core.capabilities import CapabilityFirewall, CapabilityRequest
from hot_potato.core.policy import PolicyDecision, PolicyOutcome
from hot_potato.detectors import DetectorPipeline

log = logging.getLogger("hot_potato.swarm")


class JobStatus(str, Enum):
    QUEUED     = "queued"
    RUNNING    = "running"
    DONE       = "done"
    FAILED     = "failed"


@dataclass
class SwarmJob:
    """A single artifact queued for processing."""
    artifact: TaintedArtifact
    job_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    status: JobStatus = JobStatus.QUEUED
    submitted_at: float = field(default_factory=time.monotonic)


@dataclass
class SwarmResult:
    """Result of processing one SwarmJob through the full pipeline."""
    job_id: str
    artifact: TaintedArtifact      # annotated with taint_tags after detection
    decision: PolicyDecision
    blocked: bool
    severity: str                  # cold / warm / hot / critical (from sandbox if run)
    latency_ms: float
    error: str | None = None
    sandbox_artifact: dict | None = None   # set if run_sandbox=True

    @property
    def has_injection_signals(self) -> bool:
        """True if detectors found active injection payloads in the content."""
        return self.artifact.has_injection_signals

    @property
    def clean(self) -> bool:
        """True if no injection signals were detected (content is safe to read).
        Note: tool calls may still be restricted by policy regardless of this flag."""
        return not self.has_injection_signals and self.severity in ("cold", "warm")


class ArtifactSwarm:
    """
    Concurrent artifact processing queue.

    Each submitted artifact is processed in a thread:
      1. DetectorPipeline annotates taint_tags
      2. CapabilityFirewall evaluates worst-case tool call
      3. Optionally: Docker sandbox (slow)

    Thread-safe: submit() and as_completed() can be called from any thread.
    """

    # Tool we evaluate as worst-case when checking firewall
    _PROBE_TOOL = "send_http"

    def __init__(
        self,
        workers: int = 4,
        *,
        firewall: CapabilityFirewall | None = None,
        detector_pipeline: DetectorPipeline | None = None,
        run_sandbox: bool = False,
        on_result: Callable[[SwarmResult], None] | None = None,
    ) -> None:
        self._workers = workers
        self._firewall = firewall or CapabilityFirewall()
        self._detectors = detector_pipeline or DetectorPipeline.default()
        self._run_sandbox = run_sandbox
        self._on_result = on_result

        self._executor = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="hp-swarm")
        self._pending: dict[str, Future[SwarmResult]] = {}
        self._lock = threading.Lock()
        self._closed = False

        log.info("ArtifactSwarm: %d workers, sandbox=%s", workers, run_sandbox)

    # ------------------------------------------------------------------
    # Submission
    # ------------------------------------------------------------------

    def submit(self, artifact: TaintedArtifact) -> SwarmJob:
        """Queue a single artifact for processing. Returns immediately."""
        if self._closed:
            raise RuntimeError("Swarm is closed — call reset() to reuse")
        job = SwarmJob(artifact=artifact)
        future = self._executor.submit(self._process, job)
        with self._lock:
            self._pending[job.job_id] = future
        log.debug("Swarm: submitted job %s (%s)", job.job_id, artifact.source[:60])
        return job

    def submit_many(self, artifacts: list[TaintedArtifact]) -> list[SwarmJob]:
        """Queue a batch of artifacts. Returns immediately."""
        return [self.submit(a) for a in artifacts]

    def submit_urls(self, urls: list[str], contents: list[str]) -> list[SwarmJob]:
        """Convenience: create TaintedArtifacts from URL+content pairs and queue them."""
        from hot_potato.core.taint import from_url
        return self.submit_many([from_url(u, c) for u, c in zip(urls, contents)])

    def submit_files(self, paths: list) -> list[SwarmJob]:
        """Convenience: load files and queue them as TaintedArtifacts."""
        from pathlib import Path
        from hot_potato.core.taint import from_file
        artifacts = []
        for p in paths:
            p = Path(p)
            try:
                content = p.read_text(errors="replace")
                artifacts.append(from_file(str(p), content))
            except Exception as e:
                log.warning("Could not read %s: %s", p, e)
        return self.submit_many(artifacts)

    # ------------------------------------------------------------------
    # Consuming results
    # ------------------------------------------------------------------

    def as_completed(self, timeout: float | None = None) -> Iterator[SwarmResult]:
        """Yield SwarmResults as jobs finish. Blocks until all submitted jobs complete."""
        with self._lock:
            futures = dict(self._pending)

        for future in as_completed(futures.values(), timeout=timeout):
            try:
                yield future.result()
            except Exception as e:
                log.error("Job future raised: %s", e)

    def wait(self, timeout: float | None = None) -> list[SwarmResult]:
        """Block until all submitted jobs complete. Returns all results."""
        return list(self.as_completed(timeout=timeout))

    def pending_count(self) -> int:
        with self._lock:
            return sum(1 for f in self._pending.values() if not f.done())

    def done_count(self) -> int:
        with self._lock:
            return sum(1 for f in self._pending.values() if f.done())

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def reset(self) -> None:
        """Clear completed jobs, allowing reuse for a new batch."""
        with self._lock:
            self._pending = {jid: f for jid, f in self._pending.items() if not f.done()}
        self._closed = False

    def shutdown(self, wait: bool = True) -> None:
        """Shut down the thread pool."""
        self._closed = True
        self._executor.shutdown(wait=wait)

    def __enter__(self) -> "ArtifactSwarm":
        return self

    def __exit__(self, *_: object) -> None:
        self.shutdown()

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    def summary(self, results: list[SwarmResult]) -> dict:
        """Aggregate stats across a batch of SwarmResults."""
        total = len(results)
        if not total:
            return {"total": 0}
        blocked   = [r for r in results if r.blocked]
        errors    = [r for r in results if r.error]
        clean     = [r for r in results if r.clean]
        injection = [r for r in results if r.artifact.has_injection_signals]
        avg_ms    = sum(r.latency_ms for r in results) / total
        return {
            "total": total,
            "blocked": len(blocked),
            "clean": len(clean),
            "injection_signals_detected": len(injection),
            "errors": len(errors),
            "block_rate": round(len(blocked) / total, 4),
            "avg_latency_ms": round(avg_ms, 1),
            "severity_counts": _count_severities(results),
        }

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _process(self, job: SwarmJob) -> SwarmResult:
        t0 = time.monotonic()
        artifact = job.artifact

        try:
            # Step 1: detect
            artifact = self._detectors.run(artifact)

            # Step 2: firewall — probe with worst-case tool
            req = CapabilityRequest(
                tool_name=self._PROBE_TOOL,
                args={},
                tainted_inputs=[artifact],
                requesting_model="swarm",
            )
            decision = self._firewall.evaluate(req)
            blocked = decision.is_blocked

            # Step 3: optional sandbox
            sandbox_artifact = None
            severity = "warm" if artifact.has_injection_signals else "cold"
            if self._run_sandbox:
                try:
                    from hot_potato.core.sandbox import SandboxRunner
                    sb = SandboxRunner().run(artifact.content, artifact.source)
                    sandbox_artifact = sb.artifact
                    if sb.artifact:
                        severity = sb.artifact.get("severity", severity)
                except Exception as e:
                    log.warning("Sandbox failed for job %s: %s", job.job_id, e)

            result = SwarmResult(
                job_id=job.job_id,
                artifact=artifact,
                decision=decision,
                blocked=blocked,
                severity=severity,
                latency_ms=(time.monotonic() - t0) * 1000,
                sandbox_artifact=sandbox_artifact,
            )

        except Exception as e:
            log.error("Job %s failed: %s", job.job_id, e)
            from hot_potato.core.policy import PolicyDecision, PolicyOutcome
            result = SwarmResult(
                job_id=job.job_id,
                artifact=artifact,
                decision=PolicyDecision(
                    outcome=PolicyOutcome.DENY,
                    rule_id="__error__",
                    reason=str(e),
                ),
                blocked=True,
                severity="cold",
                latency_ms=(time.monotonic() - t0) * 1000,
                error=str(e),
            )

        if self._on_result:
            try:
                self._on_result(result)
            except Exception as e:
                log.warning("on_result callback raised: %s", e)

        log.debug(
            "Swarm job %s done: blocked=%s severity=%s latency=%.1fms",
            job.job_id, result.blocked, result.severity, result.latency_ms,
        )
        return result


def _count_severities(results: list[SwarmResult]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for r in results:
        counts[r.severity] = counts.get(r.severity, 0) + 1
    return counts


__all__ = [
    "JobStatus",
    "SwarmJob",
    "SwarmResult",
    "ArtifactSwarm",
]
