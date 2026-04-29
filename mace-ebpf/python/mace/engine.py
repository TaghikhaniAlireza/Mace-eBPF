"""High-level engine FFI (init, rules, pipeline, health, allowlist)."""

from __future__ import annotations

import ctypes
from ctypes import c_char_p, c_int32, c_size_t, c_uint32

from ._ffi import get_lib


def engine_init() -> None:
    lib = get_lib()
    if not hasattr(lib, "mace_engine_init"):
        raise RuntimeError("libmace_ebpf missing mace_engine_init (rebuild Rust crate)")
    lib.mace_engine_init.argtypes = ()
    lib.mace_engine_init.restype = c_int32
    if lib.mace_engine_init() != 0:
        raise RuntimeError("mace_engine_init failed")


def load_rules_file(path: str) -> None:
    lib = get_lib()
    lib.mace_load_rules_file.argtypes = (c_char_p,)
    lib.mace_load_rules_file.restype = c_int32
    b = path.encode("utf-8")
    if lib.mace_load_rules_file(c_char_p(b)) != 0:
        raise RuntimeError(f"mace_load_rules_file failed for {path!r}")


def start_pipeline() -> None:
    lib = get_lib()
    lib.mace_start_pipeline.argtypes = ()
    lib.mace_start_pipeline.restype = c_int32
    if lib.mace_start_pipeline() != 0:
        raise RuntimeError("mace_start_pipeline failed")


def stop_pipeline() -> None:
    lib = get_lib()
    lib.mace_stop_pipeline.argtypes = ()
    lib.mace_stop_pipeline.restype = c_int32
    if lib.mace_stop_pipeline() != 0:
        raise RuntimeError("mace_stop_pipeline failed")


def allowlist_add_tgid(tgid: int) -> None:
    lib = get_lib()
    lib.mace_allowlist_add_tgid.argtypes = (c_uint32,)
    lib.mace_allowlist_add_tgid.restype = c_int32
    if lib.mace_allowlist_add_tgid(c_uint32(tgid)) != 0:
        raise RuntimeError(f"mace_allowlist_add_tgid failed for tgid={tgid}")


def engine_staged_rule_count() -> int:
    lib = get_lib()
    lib.mace_engine_staged_rule_count.argtypes = ()
    lib.mace_engine_staged_rule_count.restype = ctypes.c_uint64
    return int(lib.mace_engine_staged_rule_count())


def engine_health_json(buf_size: int = 8192) -> str:
    lib = get_lib()
    lib.mace_engine_health_json.argtypes = (ctypes.c_char_p, c_size_t)
    lib.mace_engine_health_json.restype = c_int32
    buf = ctypes.create_string_buffer(buf_size)
    rc = lib.mace_engine_health_json(buf, c_size_t(buf_size))
    if rc < 0:
        raise RuntimeError(f"health JSON needs {-rc} bytes")
    if rc != 0:
        raise RuntimeError(f"mace_engine_health_json failed rc={rc}")
    return buf.value.decode("utf-8")
