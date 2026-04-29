#!/usr/bin/env python3
"""Trigger a ptrace(PTRACE_ATTACH) syscall for mace-ebpf tracepoint validation."""

import ctypes
import os
import signal
import subprocess
import sys
import time

PTRACE_ATTACH = 16
PTRACE_DETACH = 17


def main() -> int:
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    libc.ptrace.restype = ctypes.c_long

    sleeper = subprocess.Popen(["sleep", "30"])
    print(f"[+] spawned sleep process pid={sleeper.pid}")

    attached = False
    try:
        time.sleep(0.2)
        ret = libc.ptrace(PTRACE_ATTACH, sleeper.pid, 0, 0)
        if ret != 0:
            err = ctypes.get_errno()
            print(
                f"[-] ptrace attach failed (errno={err}: {os.strerror(err)}). "
                "Try running as root and check /proc/sys/kernel/yama/ptrace_scope.",
                file=sys.stderr,
            )
            return 1

        attached = True
        os.waitpid(sleeper.pid, 0)
        print(f"[+] attached to pid={sleeper.pid}")
        print(
            f"[+] Expected sensor output: ptrace(request=0x{PTRACE_ATTACH:x}, target_pid={sleeper.pid}, ...)"
        )

        ret = libc.ptrace(PTRACE_DETACH, sleeper.pid, 0, 0)
        if ret != 0:
            err = ctypes.get_errno()
            print(
                f"[-] ptrace detach failed (errno={err}: {os.strerror(err)})",
                file=sys.stderr,
            )
            return 1
        attached = False
        print(f"[+] detached from pid={sleeper.pid}")
        return 0
    finally:
        if attached:
            libc.ptrace(PTRACE_DETACH, sleeper.pid, 0, 0)
        if sleeper.poll() is None:
            sleeper.send_signal(signal.SIGTERM)
            try:
                sleeper.wait(timeout=2)
            except subprocess.TimeoutExpired:
                sleeper.kill()
                sleeper.wait()


if __name__ == "__main__":
    raise SystemExit(main())
