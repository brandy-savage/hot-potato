"""
Native behavioral sandbox using Linux namespaces.

Replaces the Docker sandbox for hosts where Docker is unavailable or
startup latency matters.  Uses bubblewrap (bwrap) to set up:

  - User namespace  (uid 0 inside, unprivileged uid outside)
  - Mount namespace (disposable tmpfs root + read-only bind mounts)
  - PID namespace   (isolated process tree)
  - IPC namespace   (isolated SysV/POSIX IPC)
  - UTS namespace   (isolated hostname)
  - seccomp BPF     (blocks ~30 dangerous syscalls)
  - Resource limits (NPROC, AS, CPU, NOFILE)
  - NO_NEW_PRIVS    (applied by bwrap --cap-drop ALL)

Network namespace: NOT isolated by default.  The sandbox handler talks to
Ollama on localhost:11434.  Fake tool handlers never make real outbound
calls, so exfiltration is prevented at the application layer even without
kernel-level network isolation.

See docs/native_sandbox.md for the full escape vector analysis.
"""
from __future__ import annotations

import os
import resource
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Availability check
# ---------------------------------------------------------------------------

def _find_bwrap() -> Optional[str]:
    return shutil.which("bwrap") or shutil.which("bubblewrap")


def native_sandbox_available() -> bool:
    """True if bwrap is installed and unprivileged user namespaces are enabled."""
    if not _find_bwrap():
        return False
    try:
        enabled = Path("/proc/sys/kernel/unprivileged_userns_clone")
        if enabled.exists() and enabled.read_text().strip() == "0":
            return False
    except OSError:
        pass
    return True


# ---------------------------------------------------------------------------
# Resource limits applied in preexec_fn (inside the bwrap subprocess call)
# ---------------------------------------------------------------------------

def _apply_resource_limits() -> None:
    resource.setrlimit(resource.RLIMIT_NPROC,   (64,             64))
    resource.setrlimit(resource.RLIMIT_AS,       (4 * 1024 ** 3, 4 * 1024 ** 3))
    resource.setrlimit(resource.RLIMIT_CPU,      (600,           600))
    resource.setrlimit(resource.RLIMIT_NOFILE,   (1024,          1024))


# ---------------------------------------------------------------------------
# Mount helpers — figure out whether /lib, /bin etc are dirs or symlinks
# ---------------------------------------------------------------------------

def _bind_or_symlink(path: str, dest: str, symlink_target: str) -> list[str]:
    """Return bwrap args to ro-bind a path, or create a symlink if it's already a symlink."""
    p = Path(path)
    if not p.exists():
        return []
    if p.is_symlink():
        return ["--symlink", symlink_target, dest]
    return ["--ro-bind", str(p), dest]


# ---------------------------------------------------------------------------
# NativeSandbox
# ---------------------------------------------------------------------------

class NativeSandboxError(Exception):
    pass


class NativeSandbox:
    """
    Disposable-filesystem behavioral sandbox using Linux namespaces.

    Usage:
        sandbox = NativeSandbox()
        if not sandbox.available:
            raise NativeSandboxError("bwrap not installed")

        sandbox_id, workdir = sandbox.run(content, timeout=120)
        calls = parse_tool_log(Path(workdir) / "logs" / "tool_calls.jsonl")
        fs_anomalies = sandbox.check_fs(workdir)
        sandbox.cleanup(workdir)
    """

    def __init__(
        self,
        *,
        model_url: str = "http://localhost:11434",
        max_turns: int = int(os.getenv("HP_MAX_TURNS", "6")),
        model: str = os.getenv("HP_MODEL", "qwen2.5:1.5b"),
        isolate_network: bool = False,
    ):
        self.model_url = model_url
        self.max_turns = max_turns
        self.model = model
        self.isolate_network = isolate_network
        self._bwrap = _find_bwrap()

    @property
    def available(self) -> bool:
        return native_sandbox_available()

    # ------------------------------------------------------------------

    def run(self, content: str, *, timeout: int = 120) -> tuple[str, str]:
        """
        Run content through the native behavioral sandbox.

        Returns (sandbox_id, workdir) — same contract as _docker.docker_run().
        sandbox_id is a "native:<workdir>" string (not a container ID).
        workdir contains logs/tool_calls.jsonl and logs/raw_responses.jsonl.
        """
        if not self.available:
            raise NativeSandboxError(
                "bwrap not found or unprivileged user namespaces disabled. "
                "Install bubblewrap: apt install bubblewrap"
            )

        workdir = tempfile.mkdtemp(prefix="hp-native-")
        Path(workdir, "logs").mkdir()
        Path(workdir, "input.txt").write_text(content)

        seccomp_fd: Optional[int] = None
        try:
            seccomp_fd = self._make_seccomp_fd()
            cmd = self._build_bwrap_cmd(workdir, seccomp_fd)
            pass_fds = (seccomp_fd,) if seccomp_fd is not None else ()

            subprocess.run(
                cmd,
                env=self._sandbox_env(),
                timeout=timeout,
                capture_output=True,
                text=True,
                pass_fds=pass_fds,
                preexec_fn=_apply_resource_limits,
                check=False,
            )
        except subprocess.TimeoutExpired:
            pass  # logs may be partial but still useful
        finally:
            if seccomp_fd is not None:
                try:
                    os.close(seccomp_fd)
                except OSError:
                    pass

        return f"native:{workdir}", workdir

    # ------------------------------------------------------------------

    def check_fs(self, workdir: str) -> list[str]:
        """
        Audit the sandbox workdir for unexpected writes.

        The handler may write to /sandbox/logs/ — anything else is suspicious.
        Returns a list of strings in the style of `docker diff` output.
        """
        allowed_prefixes = ("logs/",)
        anomalies: list[str] = []
        base = Path(workdir)
        for p in base.rglob("*"):
            if not p.is_file():
                continue
            rel = str(p.relative_to(base))
            if not any(rel.startswith(prefix) for prefix in allowed_prefixes):
                if rel != "input.txt":
                    anomalies.append(f"C {rel}")
        return anomalies

    def cleanup(self, workdir: str) -> None:
        shutil.rmtree(workdir, ignore_errors=True)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _build_bwrap_cmd(self, workdir: str, seccomp_fd: Optional[int]) -> list[str]:
        handler = Path(__file__).parent.parent / "sandbox" / "entrypoint.py"

        cmd = [self._bwrap]

        # Namespace isolation
        cmd += [
            "--unshare-user",
            "--unshare-ipc",
            "--unshare-pid",
            "--unshare-uts",
        ]
        if self.isolate_network:
            cmd += ["--unshare-net"]

        cmd += [
            "--new-session",
            "--die-with-parent",
        ]

        # --- Mount structure ---

        # Fresh disposable root
        cmd += ["--tmpfs", "/"]

        # Python + libraries (read-only, nosuid+nodev applied automatically by bwrap)
        cmd += ["--ro-bind", "/usr", "/usr"]
        cmd += _bind_or_symlink("/lib",   "/lib",   "usr/lib")
        cmd += _bind_or_symlink("/lib64", "/lib64", "usr/lib64")
        cmd += _bind_or_symlink("/bin",   "/bin",   "usr/bin")
        cmd += _bind_or_symlink("/sbin",  "/sbin",  "usr/sbin")

        # Namespace-filtered proc (only shows sandbox PIDs)
        cmd += ["--proc", "/proc"]

        # Minimal device set: /dev/null, /dev/urandom, /dev/zero, /dev/full,
        # /dev/random, /dev/tty, /dev/pts — no block devices, no FUSE
        cmd += ["--dev", "/dev"]

        # Ephemeral writable areas (discarded on exit)
        cmd += ["--tmpfs", "/tmp"]
        cmd += ["--tmpfs", "/run"]
        cmd += ["--tmpfs", "/home"]

        # Handler script (read-only — attacker cannot modify it)
        cmd += ["--ro-bind", str(handler), "/sandbox/entrypoint.py"]

        # Sandbox work area — bind to workdir so logs survive sandbox exit
        cmd += ["--bind", workdir, "/sandbox"]

        # Drop all capabilities (bwrap also sets NO_NEW_PRIVS internally)
        cmd += ["--cap-drop", "ALL"]

        # seccomp filter
        if seccomp_fd is not None:
            cmd += ["--seccomp", str(seccomp_fd)]

        cmd += ["python3", "/sandbox/entrypoint.py"]
        return cmd

    def _sandbox_env(self) -> dict[str, str]:
        """Minimal, clean environment for the sandboxed process."""
        ollama_host = (
            self.model_url
            .replace("http://", "")
            .replace("https://", "")
        )
        return {
            "HP_MODEL":      self.model,
            "HP_MAX_TURNS":  str(self.max_turns),
            "OLLAMA_HOST":   ollama_host,
            "PATH":          "/usr/local/bin:/usr/bin:/bin",
            "HOME":          "/tmp",
            "LANG":          "C.UTF-8",
        }

    def _make_seccomp_fd(self) -> Optional[int]:
        """Build and return the seccomp filter fd, or None if it fails."""
        try:
            from hot_potato.sandbox.seccomp_filter import write_filter_to_pipe
            return write_filter_to_pipe()
        except Exception as exc:
            import sys
            print(
                f"[native-sandbox] seccomp filter unavailable ({exc}); "
                "running without — other isolation layers still active",
                file=sys.stderr,
            )
            return None


# ---------------------------------------------------------------------------
# Compatibility shim — same interface as _docker.docker_run / docker_cleanup
# ---------------------------------------------------------------------------

_DEFAULT = NativeSandbox()


def native_run(content: str, *, timeout: int = 120) -> tuple[str, str]:
    """Drop-in for docker_run(content). Returns (sandbox_id, workdir)."""
    return _DEFAULT.run(content, timeout=timeout)


def native_check_fs(sandbox_id: str) -> list[str]:
    """Drop-in for check_filesystem(container_id)."""
    if not sandbox_id.startswith("native:"):
        return []
    workdir = sandbox_id[len("native:"):]
    return _DEFAULT.check_fs(workdir)


def native_cleanup(sandbox_id: str) -> None:
    """Drop-in for docker_cleanup(container_id)."""
    if sandbox_id.startswith("native:"):
        workdir = sandbox_id[len("native:"):]
        _DEFAULT.cleanup(workdir)
