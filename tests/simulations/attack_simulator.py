#!/usr/bin/env python3
"""
Phase 2.2 — Attack simulation driver for Aegis-eBPF detection mapping.

Runs four synthetic scenarios intended to exercise eBPF + rule engine hooks:
  A) Anonymous RW mapping then mprotect(PROT_RWX)  (JIT-style RWX)
  B) Copy /bin/ls to /tmp/malicious_payload and execve it
  C) openat/read-style access to /etc/shadow (best-effort; may EPERM without privileges)
  C) ptrace(PTRACE_ATTACH) on PID 1 (expected to fail without CAP_SYS_PTRACE; syscall still observable)

Prerequisites:
  - Linux with BTF and tracepoint BPF support
  - Aegis sensor or example monitor running as **root** with rules loaded from
    `tests/simulations/rules.yaml` (or equivalent conditions)

This script does **not** start the Aegis daemon; it only generates kernel activity.
Run from the repository root, e.g.:

  sudo python3 tests/simulations/attack_simulator.py
"""

from __future__ import annotations

import ctypes
import os
import shutil
import subprocess
import sys


def scenario_a_rwx_mprotect() -> None:
    """Allocate an anonymous RW page and flip it to RWX via mprotect."""
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    libc.mmap.argtypes = [
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_long,
    ]
    libc.mmap.restype = ctypes.c_void_p
    libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
    libc.mprotect.restype = ctypes.c_int
    libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    libc.munmap.restype = ctypes.c_int

    PROT_READ = 1
    PROT_WRITE = 2
    PROT_EXEC = 4
    MAP_PRIVATE = 0x02
    MAP_ANONYMOUS = 0x20
    size = 4096

    addr = libc.mmap(
        None,
        size,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    )
    if addr == ctypes.c_void_p(-1).value:
        errno = ctypes.get_errno()
        raise OSError(errno, "mmap failed")
    try:
        rc = libc.mprotect(
            ctypes.c_void_p(addr),
            size,
            PROT_READ | PROT_WRITE | PROT_EXEC,
        )
        if rc != 0:
            errno = ctypes.get_errno()
            raise OSError(errno, "mprotect RWX failed")
    finally:
        libc.munmap(ctypes.c_void_p(addr), size)


def scenario_b_tmp_exec() -> None:
    """Copy a benign binary to /tmp and execute it (argv contains malicious_payload)."""
    dst = "/tmp/malicious_payload"
    shutil.copy2("/bin/ls", dst)
    os.chmod(dst, 0o755)
    try:
        subprocess.run([dst, "--version"], check=False, capture_output=True, timeout=5)
    finally:
        try:
            os.unlink(dst)
        except OSError:
            pass


def scenario_c_shadow_and_ptrace() -> None:
    """Trigger openat on /etc/shadow and a ptrace attach to init (both may fail safely)."""
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    # Best-effort read of shadow (often EPERM for non-root).
    subprocess.run(
        ["/bin/sh", "-c", "cat /etc/shadow >/dev/null 2>&1 || true"],
        check=False,
        timeout=5,
    )

    PTRACE_ATTACH = 16
    libc.ptrace.argtypes = [
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    libc.ptrace.restype = ctypes.c_long
    # Attach to PID 1 — typically fails; kernel still runs ptrace exit path.
    libc.ptrace(PTRACE_ATTACH, 1, None, None)


def main() -> int:
    print("[sim] Scenario A: mmap + mprotect RWX", flush=True)
    scenario_a_rwx_mprotect()

    print("[sim] Scenario B: copy /bin/ls -> /tmp/malicious_payload + execve", flush=True)
    scenario_b_tmp_exec()

    print("[sim] Scenario C: shadow read attempt + ptrace attach PID 1", flush=True)
    scenario_c_shadow_and_ptrace()

    print("[sim] Done. Check Aegis alerts / JSON sink for matched rule ids.", flush=True)
    return 0


if __name__ == "__main__":
    if os.name != "posix":
        print("This simulator requires Linux.", file=sys.stderr)
        sys.exit(2)
    # Optional: refuse non-root so operators do not confuse missing events with missing privileges.
    if os.geteuid() != 0:
        print(
            "Warning: not running as root; some scenarios may not reproduce "
            "(eBPF sensor must still run as root separately).",
            file=sys.stderr,
        )
    raise SystemExit(main())
