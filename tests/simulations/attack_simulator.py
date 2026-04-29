#!/usr/bin/env python3
"""
Phase 2.2 — Attack simulation driver for Mace-eBPF detection mapping.

Runs synthetic scenarios intended to exercise eBPF + rule engine hooks.
This script does **not** start Mace; run your monitor separately with matching rules.

**UID note:** When you run this script with `sudo`, every syscall in these scenarios
runs as **effective UID 0 (root)**. Rules that pin `uid: 1000` will **not** match simulator
traffic — use `tests/simulations/rules.yaml` (updated for uid=0 / no uid filter) or run
parts of the simulator without sudo if you need uid=1000.

Run from the repository root:

  sudo python3 tests/simulations/attack_simulator.py
"""

from __future__ import annotations

import ctypes
import os
import shutil
import subprocess
import sys


def _hdr(title: str) -> None:
    print("", flush=True)
    print("=" * 72, flush=True)
    print(title, flush=True)
    print("=" * 72, flush=True)


def _step(n: int, text: str) -> None:
    print(f"  Step {n}: {text}", flush=True)


def scenario_a_rwx_mprotect() -> None:
    """Allocate an anonymous RW page and flip it to RWX via mprotect."""
    _hdr("Scenario A — Memory: anonymous RW → RWX (mmap + mprotect)")
    print("  Goal: trigger JIT-style RWX mprotect after anonymous mmap.", flush=True)
    _step(1, "Load libc and resolve mmap/mprotect/munmap symbols.")
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

    _step(2, f"mmap(anonymous, RW, {size} bytes).")
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
    _step(3, "mprotect(same region, PROT_READ|PROT_WRITE|PROT_EXEC).")
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
        _step(4, "munmap(region).")
        libc.munmap(ctypes.c_void_p(addr), size)
    print("  Scenario A complete.", flush=True)


def scenario_b_tmp_exec() -> None:
    """Copy a benign binary to /tmp and execute it (argv contains malicious_payload)."""
    _hdr("Scenario B — Execution from /tmp (copy + execve)")
    dst = "/tmp/malicious_payload"
    _step(1, f"Copy /bin/ls → {dst}.")
    shutil.copy2("/bin/ls", dst)
    os.chmod(dst, 0o755)
    try:
        _step(2, f"execve: run `{dst} --version` (argv must contain 'malicious_payload').")
        subprocess.run([dst, "--version"], check=False, capture_output=True, timeout=5)
    finally:
        _step(3, f"Remove {dst}.")
        try:
            os.unlink(dst)
        except OSError:
            pass
    print("  Scenario B complete.", flush=True)


def scenario_c_shadow_and_ptrace() -> None:
    """Trigger openat on /etc/shadow and a ptrace attach to init (both may fail safely)."""
    _hdr("Scenario C — Sensitive read + ptrace (shell + libc)")
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    _step(1, "Spawn /bin/sh -c 'cat /etc/shadow >/dev/null 2>&1 || true' (EPERM is OK).")
    subprocess.run(
        ["/bin/sh", "-c", "cat /etc/shadow >/dev/null 2>&1 || true"],
        check=False,
        timeout=5,
    )

    PTRACE_ATTACH = 16
    _step(2, "Call ptrace(PTRACE_ATTACH, pid=1) via libc (usually EPERM without CAP_SYS_PTRACE).")
    libc.ptrace.argtypes = [
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    libc.ptrace.restype = ctypes.c_long
    libc.ptrace(PTRACE_ATTACH, 1, None, None)
    print("  Scenario C complete.", flush=True)


def main() -> int:
    print(
        f"[sim] Effective UID for this Python process: {os.geteuid()} "
        f"(use `id` in shell; sudo ⇒ 0).",
        flush=True,
    )
    scenario_a_rwx_mprotect()
    scenario_b_tmp_exec()
    scenario_c_shadow_and_ptrace()
    _hdr("All scenarios finished")
    print(
        "  If Mace is running with tests/simulations/rules.yaml, check the monitor for "
        "SIM_* rule matches.",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    if os.name != "posix":
        print("This simulator requires Linux.", file=sys.stderr)
        sys.exit(2)
    if os.geteuid() != 0:
        print(
            "Warning: not running as root; ptrace/shadow parts may behave differently. "
            "eBPF monitor is still expected to run as root separately.",
            file=sys.stderr,
        )
    raise SystemExit(main())
