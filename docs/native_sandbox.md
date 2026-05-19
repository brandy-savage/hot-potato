# Native Sandbox Design — Escape Analysis

## Problem

The Docker sandbox works but has two costs: the daemon dependency and startup time
(~3–8 s per run). This document designs a native replacement using Linux kernel
primitives, and systematically enumerates every sandbox escape vector and its mitigation.

---

## Isolation layers (applied in order)

```
1. User namespace         uid 0 inside → unprivileged uid outside
2. Mount namespace        tmpfs root, read-only bind mounts
3. PID namespace          isolated process tree (can't see host PIDs)
4. IPC namespace          isolated SysV/POSIX IPC, shared memory
5. UTS namespace          isolated hostname
6. NO_NEW_PRIVS           prctl — prevents SUID escalation forever
7. CAP_DROP ALL           all capabilities dropped post-setup
8. seccomp BPF            syscall allowlist — blocks dangerous primitives
9. Resource limits        RLIMIT_NPROC, RLIMIT_AS, RLIMIT_CPU, RLIMIT_NOFILE
```

Network namespace is omitted in the default profile because the sandbox handler
needs to reach the Ollama daemon on localhost. The fake tool handlers never make
real outbound calls, so exfiltration is prevented at the application layer even
without kernel-level network isolation.

---

## Mount structure

```
/                 tmpfs (disposable — wiped when sandbox exits)
/usr              ro-bind /usr    (Python, libs — nosuid, nodev auto-applied by bwrap)
/lib              ro-bind /lib    or symlink → usr/lib on modern distros
/lib64            ro-bind /lib64
/proc             namespace-filtered proc (shows only sandbox PIDs)
/dev              bwrap minimal device set (/dev/null, /dev/urandom, /dev/zero, /dev/tty)
/tmp              tmpfs (writable, ephemeral)
/run              tmpfs (writable, ephemeral)
/home             tmpfs (no host home directory leaks)
/sandbox          bind workdir (writable — for logs, output)
/sandbox/entrypoint.py   ro-bind to the handler script
```

Host directories NOT visible: `/root`, `/home/*` (other users), `/etc`, `/var`,
`/opt`, `/srv`, `/mnt`, `/media`, `/run/user`, `/run/secrets`.

---

## Escape vector analysis

### 1. Filesystem escapes

| Vector | Mechanism | Mitigation | Status |
|---|---|---|---|
| Symlink traversal | Symlink inside sandbox → points to host path | `pivot_root` in mount namespace — absolute paths resolve within the new root | ✓ |
| Hardlink cross-mount | Hardlink from sandbox to file on host filesystem | Root tmpfs is a different fstype; hardlinks can't cross filesystem boundaries | ✓ |
| `..` above root | Path traversal past `/` | Kernel enforces `..` at root goes to root — invariant of all mount namespaces | ✓ |
| TOCTOU on bind mounts | Race between mount and use | bwrap performs all mounts before exec; no user-controlled timing window | ✓ |
| Rename escape | Rename a sandbox dir to replace a path anchor | Inside mount namespace; renames bounded by namespace root | ✓ |
| Bind mount from inside | Call `mount()` to bind-mount a host path | `mount` syscall blocked by seccomp | ✓ |
| `pivot_root` from inside | Re-pivot to escape root | `pivot_root` blocked by seccomp | ✓ |
| `chroot` from inside | Re-chroot to escape | `chroot` blocked by seccomp; also requires CAP_SYS_CHROOT (dropped) | ✓ |

### 2. Process escapes

| Vector | Mechanism | Mitigation | Status |
|---|---|---|---|
| ptrace host process | Write to host process memory | `ptrace` blocked by seccomp | ✓ |
| `process_vm_writev` | Direct memory write to host process | `process_vm_writev` blocked by seccomp | ✓ |
| `/proc/PID/mem` write | Open host PID's mem file | PID namespace: sandbox only sees its own PIDs in `/proc`; host PIDs not exposed | ✓ |
| `/proc/self/root` link | Dereference `proc/self/root` to reach real root | Mount namespace: `proc/self/root` resolves to sandbox root, not host | ✓ |
| FD leaks from parent | Inherited open FDs to host files | `subprocess.run(close_fds=True)` + `pass_fds` only for seccomp fd; bwrap closes extras | ✓ |
| Nested namespace escape | `unshare(CLONE_NEWUSER)` inside → new uid 0 | `unshare` blocked by seccomp | ✓ |
| setns escape | Join a host namespace via fd | `setns` blocked by seccomp | ✓ |

### 3. Privilege escalation

| Vector | Mechanism | Mitigation | Status |
|---|---|---|---|
| SUID binary | Execute a SUID binary in sandbox | `nosuid` flag on all bind mounts (bwrap default); NO_NEW_PRIVS | ✓ |
| Device file access | Open `/dev/sda` etc | `nodev` flag on all bind mounts; `mknod` blocked by seccomp | ✓ |
| Capability re-acquisition | Ambient caps, cap inheritance | `CAP_DROP ALL` + `NO_NEW_PRIVS` + user namespace mapping (all caps relative to namespace) | ✓ |
| Kernel keyring abuse | `keyctl` to escalate | `keyctl`, `add_key`, `request_key` blocked by seccomp | ✓ |
| Nested user namespace | Get uid 0 in nested namespace | `unshare` blocked by seccomp; already in user namespace | ✓ |

### 4. Network escapes

| Vector | Mechanism | Mitigation | Status |
|---|---|---|---|
| External TCP/UDP | Exfiltrate via internet | Fake handlers don't call real network; policy firewall at application layer | App-layer only |
| Unix domain sockets | Connect to host sockets (D-Bus, X11, systemd) | Host socket dirs not bind-mounted (/run/user, /run/dbus etc) | ✓ |
| Netlink reconfigure | AF_NETLINK to change routing | No CAP_NET_ADMIN; netlink limited in user namespace | ✓ |
| AF_PACKET raw | Raw packet capture/injection | No CAP_NET_RAW; AF_PACKET requires it | ✓ |
| loopback to Ollama | Reach Ollama on localhost | Intentional — sandbox needs it for model calls | intentional |

**Network isolation upgrade path**: Create a separate network namespace with loopback only, then proxy Ollama calls through a parent-process HTTP relay that talks to the real daemon via a socketpair. The relay validates that requests are only to `POST /api/chat` — nothing else. Deferred to v2.

### 5. IPC escapes

| Vector | Mechanism | Mitigation | Status |
|---|---|---|---|
| SysV shared memory | `shmget`/`shmat` to shared segment | IPC namespace — isolated SysV IPC namespace | ✓ |
| POSIX message queues | `/dev/mqueue` inter-process messaging | IPC namespace; mqueue not mounted | ✓ |
| `/dev/shm` | Shared memory tmpfs | Either not mounted or fresh tmpfs | ✓ |
| memfd + exec | `memfd_create` anonymous mapping → exec shellcode | Not privileged to execute arbitrary code beyond what Python already allows; net effect same as running Python; outer uid is unprivileged | Accepted risk |

### 6. Kernel exploits

| Vector | Mechanism | Mitigation | Status |
|---|---|---|---|
| CVE in kernel | Privilege escalation via kernel bug | Unprivileged outer uid limits blast radius; seccomp reduces kernel attack surface | Partial |
| eBPF programs | Load malicious eBPF | `bpf` syscall blocked by seccomp | ✓ |
| perf_event_open | Timing side-channels, kernel exploits | `perf_event_open` blocked by seccomp | ✓ |
| kexec | Replace running kernel | `kexec_load`, `kexec_file_load` blocked by seccomp; requires CAP_SYS_BOOT (dropped) | ✓ |
| userfaultfd | Slow-fault exploitation | `userfaultfd` blocked by seccomp | ✓ |

### 7. Resource exhaustion

| Vector | Mechanism | Mitigation | Status |
|---|---|---|---|
| Fork bomb | `fork()` storm → OOM / system freeze | `RLIMIT_NPROC = 64` | ✓ |
| Memory bomb | Infinite `malloc()` | `RLIMIT_AS = 4 GB` | ✓ |
| CPU starvation | Infinite loop | `RLIMIT_CPU = 600 s`; `subprocess.run(timeout=)` as hard wall | ✓ |
| FD exhaustion | Open thousands of files | `RLIMIT_NOFILE = 1024` | ✓ |
| Disk fill | Write to sandbox workdir | `RLIMIT_FSIZE` (optional); sandbox workdir is on host — monitor size | Partial |

### 8. Information leaks (not escapes, but concerning)

| Vector | Mechanism | Mitigation |
|---|---|---|
| `/proc/net/` | Network topology of host | PID namespace `/proc` only shows sandbox processes; `/proc/net` still shows host net if no net namespace |
| Timing side-channels | Shared CPU cache / memory bus | Unavoidable in shared-kernel model |
| `/proc/cpuinfo`, `/proc/meminfo` | Hardware fingerprinting | Acceptable — no secret info |

---

## What the sandbox does NOT protect against

1. **Kernel CVEs** — any kernel privilege escalation bypasses all namespace-based isolation. Mitigated only by using an unprivileged outer uid and keeping the kernel updated.

2. **Application-layer exfil via Ollama** — if the sandboxed handler is written to actually call `send_http`, we rely on the fake handler implementation not doing so. This is a code-review concern, not a kernel-level guarantee.

3. **Timing/side-channel leaks** — shared CPU, cache, memory bus are visible to a sandboxed process. Out of scope for this threat model.

4. **Disk fill via sandbox output dir** — the output bind mount is on the host FS. A pathological model output could write large files there. Mitigated by `RLIMIT_FSIZE` and monitoring.

---

## Comparison: Docker vs native sandbox

| Property | Docker | Native (bwrap) |
|---|---|---|
| Startup time | 3–8 s | ~200 ms |
| Daemon required | Yes (dockerd) | No |
| Root required | Yes (dockerd socket) | No (user namespaces) |
| Overlay FS | Yes (container layers) | No (tmpfs) |
| Network isolation | Yes (--network none) | App-layer only (default) |
| Filesystem isolation | Yes (overlay2) | Yes (tmpfs + bind mounts) |
| seccomp | Default Docker profile | Custom (tighter) |
| Capability drop | Docker default | CAP_DROP ALL |
| Model access | Ollama inside container | Ollama via localhost |
| `docker diff` (fs audit) | Yes | Walk tmpfs output dir |

---

## Threat model fit

The sandbox is designed to catch **behavioral exfiltration**: an AI model that reads
injection content and then calls `send_http`, `bash_exec`, or `write_file` with
hostile intent. The fake handler records these calls — the sandbox prevents the fake
handler itself from being subverted to make real calls.

It is NOT designed to prevent a kernel-level attacker (CVE-grade) from escaping to
the host. For that, the outer uid's unprivileged status limits blast radius, but
true isolation requires a VM boundary.
