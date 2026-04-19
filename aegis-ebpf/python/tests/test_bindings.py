"""Tests for ctypes bindings."""

from __future__ import annotations

import unittest

from aegis import (
    AlertChannel,
    Arena,
    AegisError,
    ErrorCode,
    RawMemoryEvent,
    raw_memory_event,
)


class TestArena(unittest.TestCase):
    def test_lifecycle(self) -> None:
        arena = Arena(16)
        self.assertEqual(arena.capacity, 16)
        self.assertEqual(len(arena), 0)
        arena.close()

    def test_push_pop(self) -> None:
        with Arena(16) as arena:
            ev = raw_memory_event(
                timestamp_ns=123456789,
                tgid=1000,
                pid=2000,
                syscall_id=1,
                args=(0x7FFF0000, 64, 0, 0, 0, 0),
                cgroup_id=0,
                comm=b"test",
            )
            arena.push(ev)
            self.assertEqual(len(arena), 1)

            popped = arena.pop()
            self.assertEqual(popped.pid, 2000)
            self.assertEqual(popped.tgid, 1000)
            self.assertEqual(len(arena), 0)

    def test_overflow(self) -> None:
        # Capacity must be a power of two; for cap=4 this ring holds up to 3 events
        # before the next push returns ARENA_FULL (standard one-slot sentinel).
        with Arena(4) as arena:
            ev = raw_memory_event(
                timestamp_ns=1,
                tgid=1,
                pid=1,
                syscall_id=1,
                args=(0, 0, 0, 0, 0, 0),
                cgroup_id=0,
                comm=b"x",
            )
            arena.push(ev)
            arena.push(ev)
            arena.push(ev)
            with self.assertRaises(AegisError) as ctx:
                arena.push(ev)
            self.assertEqual(ctx.exception.code, ErrorCode.ARENA_FULL)


class TestAlertChannel(unittest.TestCase):
    def test_lifecycle(self) -> None:
        channel = AlertChannel(16)
        channel.close()

    def test_empty_recv(self) -> None:
        with AlertChannel(16) as channel:
            alert = channel.try_recv()
            self.assertIsNone(alert)


if __name__ == "__main__":
    unittest.main()
