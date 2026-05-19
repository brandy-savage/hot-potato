"""
Native behavioral sandbox using Linux namespaces.

Uses bubblewrap (bwrap) to set up:

  - User namespace  (uid mapped, unprivileged outside)
  - Mount namespace (disposable tmpfs root + read-only bind mounts)
  - PID namespace   (isolated process tree)
  - IPC namespace   (isolated SysV/POSIX IPC)
  - UTS namespace   (isolated hostname)
  - seccomp BPF     (blocks 33 dangerous syscalls — see seccomp_filter.py)
  - Resource limits via prlimit(1): NPROC=64, AS=4GB, CPU=600s, NOFILE=1024
  - NO_NEW_PRIVS    (applied by bwrap --cap-drop ALL)

Resource limits use prlimit(1) rather than preexec_fn so the implementation
is safe to call from threads (preexec_fn is not fork-safe with threads).

Symlink sanitization: after the sandbox exits, all symlinks in the workdir
bind mount are removed before the parent reads any log files. Without this,
the sandbox can plant a symlink in /sandbox (the bind mount) that the parent
follows into arbitrary host paths — a confirmed escape vector.

Network namespace: NOT isolated by default. The sandbox handler talks to
Ollama on localhost:11434. Fake tool handlers never make real outbound calls,
so exfiltration is prevented at the application layer.

See docs/native_sandbox.md for the full escape vector analysis.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Availability check
# ---------------------------------------------------------------------------

def _find_bwrap() -> Optional[str]:
    return shutil.which("bwrap") or shutil.which("bubblewrap")


def _find_prlimit() -> Optional[str]:
    return shutil.which("prlimit")


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
# Symlink sanitizer — MUST run before parent reads any workdir files
# ---------------------------------------------------------------------------

def _purge_symlinks(workdir: str) -> list[str]:
    """
    Recursively remove all symlinks from the workdir bind mount.

    Without this, the sandbox can plant a symlink like:
        /sandbox/logs/tool_calls.jsonl -> /home/user/.ssh/id_rsa
    and when the parent calls parse_tool_log(workdir / 'logs' / 'tool_calls.jsonl')
    it follows the symlink and reads an arbitrary host file.

    Uses os.scandir() with follow_symlinks=False throughout — never follows
    any symlink during the traversal itself.

    Returns list of paths that were removed (for audit logging).
    """
    removed: list[str] = []
    queue: list[Path] = [Path(workdir)]

    while queue:
        current = queue.pop()
        try:
            with os.scandir(current) as it:
                for entry in it:
                    if entry.is_symlink():
                        os.unlink(entry.path)
                        removed.append(entry.path)
                    elif entry.is_dir(follow_symlinks=False):
                        queue.append(Path(entry.path))
        except (PermissionError, FileNotFoundError):
            pass

    return removed


# ---------------------------------------------------------------------------
# Mount helpers
# ---------------------------------------------------------------------------

def _bind_or_symlink(path: str, dest: str, symlink_target: str) -> list[str]:
    """Return bwrap args to ro-bind a path, or create a symlink if already a symlink."""
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
        # workdir is safe to read — symlinks have been purged
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
        self._prlimit = _find_prlimit()

    @property
    def available(self) -> bool:
        return native_sandbox_available()

    # ------------------------------------------------------------------

    def run(self, content: str, *, timeout: int = 120) -> tuple[str, str]:
        """
        Run content through the native behavioral sandbox.

        Returns (sandbox_id, workdir).
        workdir is safe to read — symlinks planted by the sandbox are purged
        before this method returns.
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
                # No preexec_fn — not safe with threads. Resource limits are
                # applied via prlimit(1) inside the bwrap command instead.
                check=False,
            )
        except subprocess.TimeoutExpired:
            pass  # partial logs are still useful
        finally:
            if seccomp_fd is not None:
                try:
                    os.close(seccomp_fd)
                except OSError:
                    pass

        # Purge symlinks BEFORE returning the workdir to any caller.
        # This prevents the sandbox from using the bind mount to plant
        # symlinks that the parent would follow into host FS paths.
        removed = _purge_symlinks(workdir)
        if removed:
            print(
                f"[native-sandbox] WARNING: removed {len(removed)} symlink(s) "
                f"planted by sandbox sandbox: {removed}",
                file=sys.stderr,
            )

        return f"native:{workdir}", workdir

    # ------------------------------------------------------------------

    def check_fs(self, workdir: str) -> list[str]:
        """
        Audit the sandbox workdir for unexpected writes.

        Uses os.scandir() with follow_symlinks=False — never follows symlinks.
        Any remaining symlinks (should be zero after _purge_symlinks) are
        reported as anomalies.
        """
        allowed_prefixes = ("logs/",)
        anomalies: list[str] = []
        base = Path(workdir)
        queue: list[Path] = [base]

        while queue:
            current = queue.pop()
            try:
                with os.scandir(current) as it:
                    for entry in it:
                        rel = str(Path(entry.path).relative_to(base))
                        if entry.is_symlink():
                            # Should have been purged — flag as critical anomaly
                            target = os.readlink(entry.path)
                            anomalies.append(f"S {rel} -> {target}")
                        elif entry.is_dir(follow_symlinks=False):
                            queue.append(Path(entry.path))
                        elif entry.is_file(follow_symlinks=False):
                            if rel != "input.txt" and not any(
                                rel.startswith(p) for p in allowed_prefixes
                            ):
                                anomalies.append(f"C {rel}")
            except (PermissionError, FileNotFoundError):
                pass

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

        # Fresh disposable root (every byte is ephemeral)
        cmd += ["--tmpfs", "/"]

        # Python + libraries (read-only; nosuid+nodev applied automatically by bwrap)
        cmd += ["--ro-bind", "/usr", "/usr"]
        cmd += _bind_or_symlink("/lib",   "/lib",   "usr/lib")
        cmd += _bind_or_symlink("/lib64", "/lib64", "usr/lib64")
        cmd += _bind_or_symlink("/bin",   "/bin",   "usr/bin")
        cmd += _bind_or_symlink("/sbin",  "/sbin",  "usr/sbin")

        # Namespace-filtered /proc (shows only sandbox PIDs)
        cmd += ["--proc", "/proc"]

        # Minimal device set (/dev/null, /dev/urandom, /dev/zero, /dev/tty — no block devs)
        cmd += ["--dev", "/dev"]

        # Ephemeral writable areas (vanish when sandbox exits)
        cmd += ["--tmpfs", "/tmp"]
        cmd += ["--tmpfs", "/run"]
        cmd += ["--tmpfs", "/home"]

        # Handler script (read-only — sandbox cannot modify it)
        cmd += ["--ro-bind", str(handler), "/sandbox/entrypoint.py"]

        # Workdir bind mount (writable — for logs/output; symlinks purged post-exit)
        cmd += ["--bind", workdir, "/sandbox"]

        # Drop all capabilities (bwrap also sets NO_NEW_PRIVS)
        cmd += ["--cap-drop", "ALL"]

        # seccomp filter
        if seccomp_fd is not None:
            cmd += ["--seccomp", str(seccomp_fd)]

        # Resource limits via prlimit(1) — thread-safe, unlike preexec_fn.
        # prlimit is in /usr/bin (bind-mounted via /usr).
        if self._prlimit:
            cmd += [
                "prlimit",
                "--nproc=64",                          # max child processes
                f"--as={4 * 1024 * 1024 * 1024}",     # 4 GB virtual address space
                "--cpu=600",                           # 10 min CPU time
                "--nofile=1024",                       # max open file descriptors
            ]

        cmd += ["python3", "/sandbox/entrypoint.py"]
        return cmd

    def _sandbox_env(self) -> dict[str, str]:
        """Minimal, clean environment — no host env vars leak into sandbox."""
        ollama_host = (
            self.model_url
            .replace("http://", "")
            .replace("https://", "")
        )
        return {
            "HP_MODEL":     self.model,
            "HP_MAX_TURNS": str(self.max_turns),
            "OLLAMA_HOST":  ollama_host,
            "PATH":         "/usr/local/bin:/usr/bin:/bin",
            "HOME":         "/tmp",
            "LANG":         "C.UTF-8",
        }

    def _make_seccomp_fd(self) -> Optional[int]:
        """
        Build and return the seccomp filter fd.

        Raises NativeSandboxError on failure unless HP_SECCOMP_OPTIONAL=1.
        Fail-open is only acceptable in dev/test environments where you
        explicitly know the filter won't load (e.g. no kernel BPF support).
        """
        try:
            from hot_potato.sandbox.seccomp_filter import write_filter_to_pipe
            return write_filter_to_pipe()
        except Exception as exc:
            if os.getenv("HP_SECCOMP_OPTIONAL") == "1":
                print(
                    f"[native-sandbox] WARNING: seccomp filter unavailable ({exc}); "
                    "HP_SECCOMP_OPTIONAL=1 — proceeding without (dev/test only)",
                    file=sys.stderr,
                )
                return None
            raise NativeSandboxError(
                f"seccomp filter failed to build: {exc}. "
                "Set HP_SECCOMP_OPTIONAL=1 to run without (not recommended)."
            ) from exc


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
