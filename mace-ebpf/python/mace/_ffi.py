"""Load ``libmace_ebpf`` and attach ctypes signatures."""

from __future__ import annotations

import ctypes
from ctypes import POINTER, c_int32, c_size_t, c_uint8, c_void_p

from .types import RawMemoryEvent, lib_path

# Initialized lazily by ``load_lib`` so importing the package never touches ``_lib``
# before ``lib_path()`` is valid (and so ``__del__`` never sees ``NameError``).
_lib: ctypes.CDLL | None = None


def load_lib() -> ctypes.CDLL:
    """Load the shared library once and bind strict ``argtypes`` / ``restype`` for every FFI symbol."""
    global _lib
    path = lib_path()
    if not path.is_file():
        raise FileNotFoundError(
            f"Shared library not found at {path}. "
            "Run `cargo build -p mace-ebpf` from the workspace root."
        )
    lib = ctypes.CDLL(str(path))

    lib.mace_arena_new.argtypes = (c_size_t,)
    lib.mace_arena_new.restype = c_void_p

    lib.mace_arena_free.argtypes = (c_void_p,)
    lib.mace_arena_free.restype = None

    lib.mace_arena_push.argtypes = (c_void_p, POINTER(RawMemoryEvent))
    lib.mace_arena_push.restype = c_int32

    lib.mace_arena_pop.argtypes = (c_void_p, POINTER(RawMemoryEvent))
    lib.mace_arena_pop.restype = c_int32

    lib.mace_arena_try_push.argtypes = (c_void_p, POINTER(RawMemoryEvent))
    lib.mace_arena_try_push.restype = c_int32

    lib.mace_arena_try_pop.argtypes = (c_void_p, POINTER(RawMemoryEvent))
    lib.mace_arena_try_pop.restype = c_int32

    lib.mace_arena_len.argtypes = (c_void_p,)
    lib.mace_arena_len.restype = c_size_t

    lib.mace_arena_capacity.argtypes = (c_void_p,)
    lib.mace_arena_capacity.restype = c_size_t

    class JitStormStats(ctypes.Structure):
        _fields_ = [
            ("requested", ctypes.c_uint64),
            ("pushed", ctypes.c_uint64),
            ("popped", ctypes.c_uint64),
            ("full_retries", ctypes.c_uint64),
        ]

    lib.mace_simulate_jit_storm.argtypes = (c_void_p, ctypes.c_uint32, ctypes.POINTER(JitStormStats))
    lib.mace_simulate_jit_storm.restype = c_int32

    lib.mace_alert_channel_new.argtypes = (c_size_t,)
    lib.mace_alert_channel_new.restype = c_void_p

    lib.mace_alert_channel_free.argtypes = (c_void_p,)
    lib.mace_alert_channel_free.restype = None

    lib.mace_alert_channel_try_recv.argtypes = (c_void_p, POINTER(c_uint8), c_size_t)
    lib.mace_alert_channel_try_recv.restype = c_int32

    lib.mace_alert_channel_feed_test_alert.argtypes = (c_void_p,)
    lib.mace_alert_channel_feed_test_alert.restype = c_int32

    _lib = lib
    return lib


def get_lib() -> ctypes.CDLL:
    if _lib is None:
        return load_lib()
    return _lib
