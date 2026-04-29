#!/usr/bin/env python3
"""Trigger a memfd_create syscall for mace-ebpf tracepoint validation."""

import os


def main() -> int:
    name = "mace-ebpf-memfd-test"
    payload = b"mace-ebpf memfd payload\n"

    fd = os.memfd_create(name, flags=0)
    try:
        written = os.write(fd, payload)
        os.lseek(fd, 0, os.SEEK_SET)
        echoed = os.read(fd, len(payload))
    finally:
        os.close(fd)

    print(f"[+] memfd fd={fd} created with name={name!r}")
    print(f"[+] wrote {written} bytes")
    print(f"[+] read back: {echoed!r}")
    print("[+] Expected sensor output: memfd_create(..., flags=0x0)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
