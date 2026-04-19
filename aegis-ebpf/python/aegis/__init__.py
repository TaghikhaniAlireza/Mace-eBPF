"""Python ctypes bindings for the Aegis-eBPF SDK."""

from __future__ import annotations

from .alert import AlertChannel
from .arena import Arena
from .types import (
    AegisError,
    ErrorCode,
    RawMemoryEvent,
    raw_memory_event,
)

__all__ = [
    "AlertChannel",
    "Arena",
    "AegisError",
    "ErrorCode",
    "RawMemoryEvent",
    "raw_memory_event",
]
