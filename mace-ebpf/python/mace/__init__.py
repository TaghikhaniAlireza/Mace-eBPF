"""Python ctypes bindings for the Mace-eBPF SDK."""

from __future__ import annotations

from .alert import AlertChannel
from .arena import Arena
from .engine import (
    allowlist_add_tgid,
    engine_health_json,
    engine_init,
    engine_staged_rule_count,
    load_rules_file,
    start_pipeline,
    stop_pipeline,
)
from .types import (
    MaceError,
    ErrorCode,
    RawMemoryEvent,
    raw_memory_event,
)

__all__ = [
    "AlertChannel",
    "Arena",
    "MaceError",
    "ErrorCode",
    "RawMemoryEvent",
    "raw_memory_event",
    "engine_init",
    "load_rules_file",
    "start_pipeline",
    "stop_pipeline",
    "allowlist_add_tgid",
    "engine_health_json",
    "engine_staged_rule_count",
]
