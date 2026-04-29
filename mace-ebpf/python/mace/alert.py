"""Alert channel FFI wrapper and protobuf deserialization."""

from __future__ import annotations

import ctypes
from ctypes import c_uint8

from ._ffi import get_lib
from .types import MaceError, ErrorCode


def _alert_pb2():
    from .proto import alert_pb2

    return alert_pb2


class AlertChannel:
    """Poll-based consumer for protobuf alerts from ``mace_alert_channel_try_recv``."""

    __slots__ = ("_handle", "_initial_buf_size")

    def __init__(self, capacity: int) -> None:
        self._handle = None
        self._initial_buf_size = 4096
        if capacity <= 0:
            raise ValueError("capacity must be positive")
        lib = get_lib()
        self._handle = lib.mace_alert_channel_new(ctypes.c_size_t(capacity))
        if not self._handle:
            self._handle = None
            raise MaceError("failed to create alert channel")

    def try_recv(self):
        """Return the next ``Alert`` message, or ``None`` if none / empty."""
        lib = get_lib()
        alert_pb2 = _alert_pb2()
        buf = (c_uint8 * self._initial_buf_size)()

        if self._handle is None:
            raise MaceError("alert channel is closed", ErrorCode.NULL_POINTER)

        while True:
            result = int(
                lib.mace_alert_channel_try_recv(
                    self._handle,
                    buf,
                    ctypes.c_size_t(ctypes.sizeof(buf)),
                )
            )

            if result == 0:
                return None

            if result in (ErrorCode.NULL_POINTER, ErrorCode.PANIC):
                raise MaceError(
                    f"mace_alert_channel_try_recv failed: {result}",
                    ErrorCode(result),
                )

            if result < 0:
                need = -result
                if need <= 0 or need > 16 * 1024 * 1024:
                    raise MaceError(
                        "invalid buffer size requirement from FFI",
                        ErrorCode.DECODE_ERROR,
                    )
                buf = (c_uint8 * need)()
                self._initial_buf_size = need
                continue

            data = bytes(memoryview(buf)[:result])
            msg = alert_pb2.Alert()
            try:
                msg.ParseFromString(data)
            except Exception as exc:
                raise MaceError(
                    f"protobuf decode failed: {exc}",
                    ErrorCode.DECODE_ERROR,
                ) from exc
            return msg

    def close(self) -> None:
        """Release the native alert channel handle; idempotent."""
        handle = getattr(self, "_handle", None)
        if handle is None:
            return
        self._handle = None
        try:
            get_lib().mace_alert_channel_free(handle)
        except Exception:
            pass

    def __enter__(self) -> AlertChannel:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


__all__ = ["AlertChannel"]
