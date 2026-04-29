"""Arena FFI wrapper."""

from __future__ import annotations

import ctypes
from ctypes import byref

from ._ffi import get_lib
from .types import MaceError, ErrorCode, RawMemoryEvent, _check_arena_code, raw_memory_event


def _ensure_power_of_two(capacity: int) -> None:
    if capacity <= 0:
        raise ValueError("capacity must be positive")
    if capacity & (capacity - 1) != 0:
        raise ValueError(
            "capacity must be a power of two (required by the Rust ring buffer)"
        )


class Arena:
    """Ring-buffer arena for :class:`RawMemoryEvent` values."""

    __slots__ = ("_handle",)

    def __init__(self, capacity: int) -> None:
        # Always defined so ``__del__`` / ``close`` never hit ``AttributeError`` during failed init.
        self._handle = None
        _ensure_power_of_two(capacity)
        lib = get_lib()
        self._handle = lib.mace_arena_new(ctypes.c_size_t(capacity))
        if not self._handle:
            self._handle = None
            raise MaceError("failed to create arena (invalid capacity or Rust panic)")

    def _require_handle(self) -> ctypes.c_void_p:
        if self._handle is None:
            raise MaceError("arena is closed", ErrorCode.NULL_POINTER)
        return self._handle

    def push(self, event: RawMemoryEvent) -> None:
        lib = get_lib()
        code = int(lib.mace_arena_push(self._require_handle(), byref(event)))
        _check_arena_code(code, "mace_arena_push")

    def pop(self) -> RawMemoryEvent:
        lib = get_lib()
        out = RawMemoryEvent()
        code = int(lib.mace_arena_pop(self._require_handle(), byref(out)))
        _check_arena_code(code, "mace_arena_pop")
        return out

    def __len__(self) -> int:
        lib = get_lib()
        return int(lib.mace_arena_len(self._require_handle()))

    @property
    def capacity(self) -> int:
        lib = get_lib()
        return int(lib.mace_arena_capacity(self._require_handle()))

    def close(self) -> None:
        """Release the native arena handle; safe to call multiple times or from ``__del__``."""
        handle = getattr(self, "_handle", None)
        if handle is None:
            return
        self._handle = None
        try:
            get_lib().mace_arena_free(handle)
        except Exception:
            # During interpreter shutdown ``get_lib()`` can fail; Rust ``mace_arena_free(NULL)`` is
            # safe but we already cleared the Python side to avoid double-free.
            pass

    def __enter__(self) -> Arena:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


__all__ = ["Arena"]
