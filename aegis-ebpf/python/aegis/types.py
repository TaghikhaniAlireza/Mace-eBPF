"""ctypes types and errors for the Aegis C API."""

from __future__ import annotations

import enum
from ctypes import Structure, c_uint32, c_uint64, c_uint8, c_int32, c_size_t
from pathlib import Path
from typing import Optional, Sequence, Union

# --- Error codes (match `AegisErrorCode` in aegis.h; negative values). ---


class ErrorCode(enum.IntEnum):
    SUCCESS = 0
    NULL_POINTER = -1
    ARENA_FULL = -2
    ARENA_EMPTY = -3
    PANIC = -4
    # Python-layer only (not returned by Rust FFI):
    CHANNEL_CLOSED = -100
    DECODE_ERROR = -101


class AegisError(RuntimeError):
    """Raised when an FFI call returns an error code or validation fails."""

    def __init__(self, message: str, code: Optional[ErrorCode] = None):
        super().__init__(message)
        self.code = code


def _check_arena_code(code: int, operation: str) -> None:
    if code == ErrorCode.SUCCESS:
        return
    try:
        ec = ErrorCode(code)
    except ValueError:
        raise AegisError(f"{operation}: unexpected error code {code}", None) from None
    raise AegisError(f"{operation}: {ec.name} ({int(ec)})", ec)


# --- RawMemoryEvent (must match include/aegis.h) ---


class RawMemoryEvent(Structure):
    _pack_ = 8
    _fields_ = [
        ("timestamp_ns", c_uint64),
        ("tgid", c_uint32),
        ("pid", c_uint32),
        ("syscall_id", c_uint32),
        ("_pad0", c_uint32),
        ("args", c_uint64 * 6),
        ("cgroup_id", c_uint64),
        ("comm", c_uint8 * 16),
    ]


def raw_memory_event(
    *,
    timestamp_ns: int = 0,
    tgid: int = 0,
    pid: int = 0,
    syscall_id: int = 0,
    args: Optional[Sequence[int]] = None,
    cgroup_id: int = 0,
    comm: Union[bytes, str] = b"",
) -> RawMemoryEvent:
    """Build a :class:`RawMemoryEvent` from Python values."""
    if args is None:
        args = [0] * 6
    elif len(args) != 6:
        raise ValueError("args must have length 6")

    data = comm.encode() if isinstance(comm, str) else comm
    if len(data) > 15:
        raise ValueError("comm must be at most 15 bytes (+ NUL)")

    ev = RawMemoryEvent()
    ev.timestamp_ns = timestamp_ns
    ev.tgid = tgid
    ev.pid = pid
    ev.syscall_id = syscall_id
    ev._pad0 = 0
    for i in range(6):
        ev.args[i] = int(args[i])
    ev.cgroup_id = cgroup_id
    for i in range(16):
        ev.comm[i] = data[i] if i < len(data) else 0
    return ev


def lib_path() -> Path:
    """Path to ``libaegis_ebpf`` next to the workspace ``target/debug`` directory."""
    here = Path(__file__).resolve()
    # aegis-ebpf/python/aegis/types.py -> workspace root is parents[3]
    repo_root = here.parents[3]
    debug = repo_root / "target" / "debug"
    import sys

    if sys.platform == "darwin":
        return debug / "libaegis_ebpf.dylib"
    return debug / "libaegis_ebpf.so"


__all__ = [
    "AegisError",
    "ErrorCode",
    "RawMemoryEvent",
    "raw_memory_event",
    "lib_path",
    "_check_arena_code",
]
