"""Load ``libaegis_ebpf`` and attach ctypes signatures."""

from __future__ import annotations

import ctypes
from ctypes import POINTER, c_int32, c_size_t, c_uint8, c_void_p

from .types import RawMemoryEvent, lib_path

_lib: ctypes.CDLL


def load_lib() -> ctypes.CDLL:
    global _lib
    path = lib_path()
    if not path.is_file():
        raise FileNotFoundError(
            f"Shared library not found at {path}. "
            "Run `cargo build -p aegis-ebpf` from the workspace root."
        )
    _lib = ctypes.CDLL(str(path))
    _lib.aegis_arena_new.argtypes = [c_size_t]
    _lib.aegis_arena_new.restype = c_void_p

    _lib.aegis_arena_free.argtypes = [c_void_p]
    _lib.aegis_arena_free.restype = None

    _lib.aegis_arena_push.argtypes = [c_void_p, POINTER(RawMemoryEvent)]
    _lib.aegis_arena_push.restype = c_int32

    _lib.aegis_arena_pop.argtypes = [c_void_p, POINTER(RawMemoryEvent)]
    _lib.aegis_arena_pop.restype = c_int32

    _lib.aegis_arena_try_push.argtypes = [c_void_p, POINTER(RawMemoryEvent)]
    _lib.aegis_arena_try_push.restype = c_int32

    _lib.aegis_arena_try_pop.argtypes = [c_void_p, POINTER(RawMemoryEvent)]
    _lib.aegis_arena_try_pop.restype = c_int32

    _lib.aegis_arena_len.argtypes = [c_void_p]
    _lib.aegis_arena_len.restype = c_size_t

    _lib.aegis_arena_capacity.argtypes = [c_void_p]
    _lib.aegis_arena_capacity.restype = c_size_t

    _lib.aegis_alert_channel_new.argtypes = [c_size_t]
    _lib.aegis_alert_channel_new.restype = c_void_p

    _lib.aegis_alert_channel_free.argtypes = [c_void_p]
    _lib.aegis_alert_channel_free.restype = None

    _lib.aegis_alert_channel_try_recv.argtypes = [c_void_p, POINTER(c_uint8), c_size_t]
    _lib.aegis_alert_channel_try_recv.restype = c_int32

    return _lib


def get_lib() -> ctypes.CDLL:
    try:
        return _lib
    except NameError:
        return load_lib()
