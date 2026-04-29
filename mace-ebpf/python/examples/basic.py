#!/usr/bin/env python3
"""Minimal example: arena push/pop and empty alert channel."""

from __future__ import annotations

import sys
import time
from pathlib import Path

# Allow running without install: ``python examples/basic.py`` from python/
_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from mace import AlertChannel, Arena, raw_memory_event


def main() -> None:
    with Arena(1024) as arena:
        print(f"Arena capacity: {arena.capacity}")

        for i in range(10):
            event = raw_memory_event(
                timestamp_ns=int(time.time() * 1e9),
                tgid=1000 + i,
                pid=2000 + i,
                syscall_id=1,
                args=(0x7FFF0000 + i * 0x1000, 64, 0, 0, 0, 0),
                cgroup_id=0,
                comm=f"test-{i}".encode(),
            )
            arena.push(event)

        print(f"Events in arena: {len(arena)}")

        while len(arena) > 0:
            event = arena.pop()
            print(
                f"Event: PID={event.pid} TGID={event.tgid} "
                f"Addr=0x{event.args[0]:x} Size={event.args[1]}"
            )

    with AlertChannel(256) as alerts:
        alert = alerts.try_recv()
        if alert:
            print(f"Alert: {alert.message} (severity: {alert.severity})")
        else:
            print("No alerts available")


if __name__ == "__main__":
    main()
