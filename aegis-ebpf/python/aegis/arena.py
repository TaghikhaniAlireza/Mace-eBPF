"""Arena FFI wrapper."""

from __future__ import annotations

import ctypes
from ctypes import byref

from ._ffi import get_lib
from .types import AegisError, ErrorCode, RawMemoryEvent, _check_arena_code, raw_memory_event


def _ensure_power_of_two(capacity: int) -> None:
    if capacity <= 0:
        raise ValueError("capacity must be positive")
    if capacity & (capacity - 1) != 0:
        raise ValueError(
            "capacity must be a power of two (required by the Rust ring buffer)"
        )


class Arena:
    """Ring-buffer arena for :class:`RawMemoryEvent` values."""

    def __init__(self, capacity: int) -> None:
        _ensure_power_of_two(capacity)
        lib = get_lib()
        self._handle = lib.aegis_arena_new(ctypes.c_size_t(capacity))
        if not self._handle:
            raise AegisError("failed to create arena (invalid capacity or Rust panic)")

    def push(self, event: RawMemoryEvent) -> None:
        lib = get_lib()
        code = int(lib.aegis_arena_push(self._handle, byref(event)))
        _check_arena_code(code, "aegis_arena_push")

    def pop(self) -> RawMemoryEvent:
        lib = get_lib()
        out = RawMemoryEvent()
        code = int(lib.aegis_arena_pop(self._handle, byref(out)))
        _check_arena_code(code, "aegis_arena_pop")
        return out

    def __len__(self) -> int:
        lib = get_lib()
        return int(lib.aegis_arena_len(self._handle))

    @property
    def capacity(self) -> int:
        lib = get_lib()
        return int(lib.aegis_arena_capacity(self._handle))

    def close(self) -> None:
        if self._handle:
            lib = get_lib()
            lib.aegis_arena_free(self._handle)
            self._handle = None

    def __enter__(self) -> Arena:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def __del__(self) -> None:
        self.close()


__all__ = ["Arena"]
