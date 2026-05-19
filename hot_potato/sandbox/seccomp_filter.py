"""
Build a seccomp BPF filter that blocks dangerous syscalls while allowing
everything else.  No libseccomp dependency — pure ctypes/struct.

The filter is intended to be loaded by bubblewrap (bwrap) via --seccomp <fd>.
bwrap reads raw struct sock_filter bytes from the fd and installs the filter
with prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ...).

BPF instruction layout (struct sock_filter, 8 bytes each):
  u16 code   — opcode
  u8  jt     — jump-if-true offset
  u8  jf     — jump-if-false offset
  u32 k      — immediate / address

seccomp_data layout (what the filter has access to):
  u32 nr      @ offset 0   — syscall number (what we check)
  u32 arch    @ offset 4   — architecture
  u64 ip      @ offset 8
  u64 args[6] @ offset 16
"""
from __future__ import annotations

import struct

# ---------------------------------------------------------------------------
# BPF constants
# ---------------------------------------------------------------------------
BPF_LD   = 0x00
BPF_W    = 0x00
BPF_ABS  = 0x20
BPF_JMP  = 0x05
BPF_JEQ  = 0x10
BPF_K    = 0x00
BPF_RET  = 0x06

SECCOMP_RET_ALLOW = 0x7FFF_0000
SECCOMP_RET_ERRNO = 0x0005_0000  # base — OR with errno value
EPERM = 1

SECCOMP_DATA_NR_OFFSET = 0  # offset of syscall nr in seccomp_data


def _stmt(code: int, k: int) -> bytes:
    return struct.pack("<HBBI", code, 0, 0, k)


def _jump(code: int, k: int, jt: int, jf: int) -> bytes:
    return struct.pack("<HBBI", code, jt, jf, k)


# ---------------------------------------------------------------------------
# x86_64 syscall numbers for the calls we want to block.
# Source: linux/arch/x86/entry/syscalls/syscall_64.tbl (kernel 6.x)
# ---------------------------------------------------------------------------
_BLOCKED: dict[str, int] = {
    # Process inspection / injection
    "ptrace":              101,
    "process_vm_readv":    310,
    "process_vm_writev":   311,
    # Namespace manipulation (prevent sandbox-inside-sandbox escapes)
    "unshare":             272,
    "setns":               308,
    # Filesystem namespace manipulation
    "mount":               165,
    "umount2":             166,
    "pivot_root":          155,
    "chroot":              161,
    # Device / special file creation
    "mknod":               133,
    "mknodat":             259,
    # File handle open (Shocker-style container escape vector)
    "open_by_handle_at":   304,
    # Kernel keyring (key exfiltration / persistence)
    "keyctl":              250,
    "add_key":             248,
    "request_key":         249,
    # Performance counter / eBPF (kernel exploit surface)
    "perf_event_open":     298,
    "bpf":                 321,
    # Kernel loading / replacement
    "kexec_load":          246,
    "kexec_file_load":     320,
    "init_module":         175,
    "finit_module":        313,
    "delete_module":       176,
    # Userfaultfd (exploit primitive for use-after-free)
    "userfaultfd":         323,
    # Privileged system operations
    "reboot":              169,
    "swapon":              167,
    "swapoff":             168,
    "acct":                163,
    "syslog":              103,
    "quotactl":            179,
    "iopl":                172,
    "ioperm":              173,
    # vmsplice (pipe-to-arbitrary-mapping exploit primitive)
    "vmsplice":            278,
    # Lookup own credentials in new namespace (helps prevent uid confusion attacks)
    "lookup_dcookie":      212,
}


def build_filter() -> bytes:
    """
    Return raw BPF bytecode (sequence of struct sock_filter, 8 bytes each)
    implementing:
      - load seccomp_data.nr (syscall number)
      - for each blocked syscall: if nr == X → return ERRNO(EPERM)
      - default: return ALLOW
    """
    insns: list[bytes] = []

    # Load the syscall number into accumulator
    insns.append(_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR_OFFSET))

    for name, nr in sorted(_BLOCKED.items(), key=lambda x: x[1]):
        # if A == nr → jt=0 (fall through to DENY), else jf=1 (skip DENY)
        insns.append(_jump(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 1))
        insns.append(_stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM))

    # Default: allow
    insns.append(_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW))

    return b"".join(insns)


def write_filter_to_pipe() -> int:
    """
    Write the seccomp BPF filter to a pipe and return the read-end fd.
    The write end is closed immediately.  The caller passes the read fd
    to bwrap via --seccomp <fd>.
    """
    import os
    bpf = build_filter()
    r, w = os.pipe()
    os.write(w, bpf)
    os.close(w)
    return r


def verify_filter() -> None:
    """Smoke-test: verify the filter compiles to a non-empty multiple of 8 bytes."""
    bpf = build_filter()
    assert len(bpf) > 0 and len(bpf) % 8 == 0, f"bad filter length: {len(bpf)}"
    n_instructions = len(bpf) // 8
    # Sanity: at most 32768 instructions (kernel limit)
    assert n_instructions <= 32768, "filter exceeds kernel BPF limit"
    print(f"seccomp filter: {n_instructions} instructions, {len(bpf)} bytes — OK")
    print(f"blocked syscalls: {len(_BLOCKED)}")


if __name__ == "__main__":
    verify_filter()
