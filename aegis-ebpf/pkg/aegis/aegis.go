// Package aegis provides Go bindings for the Aegis-eBPF SDK.
//
// This package wraps the Rust-based security monitoring library with idiomatic Go
// interfaces, automatic cleanup via runtime.SetFinalizer on Sensor, and
// channel-based delivery for arena events and protobuf alerts.
package aegis

/*
#cgo CFLAGS: -I${SRCDIR}/../../include
// Static link (no libaegis_ebpf.so). Default: debug artifact — `cargo build -p aegis-ebpf`.
// Release: `cargo build --release -p aegis-ebpf` then `go build -tags aegis_static_release`.
#cgo !aegis_static_release LDFLAGS: ${SRCDIR}/../../../target/debug/libaegis_ebpf.a -ldl -lpthread -lm -lgcc_s
#cgo aegis_static_release LDFLAGS: ${SRCDIR}/../../../target/release/libaegis_ebpf.a -ldl -lpthread -lm -lgcc_s

#include <stdlib.h>
#include "aegis.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"runtime"
)

// ErrorCode represents FFI error codes from the Rust library (arena operations).
type ErrorCode int32

const (
	Success     ErrorCode = 0
	NullPointer ErrorCode = -1
	ArenaFull   ErrorCode = -2
	ArenaEmpty  ErrorCode = -3
	Panic       ErrorCode = -4
)

// ErrClosed is returned when calling methods on a closed Sensor.
var ErrClosed = errors.New("aegis: sensor closed")

// Error implements error.
func (e ErrorCode) Error() string {
	switch e {
	case Success:
		return "success"
	case NullPointer:
		return "null pointer"
	case ArenaFull:
		return "arena full"
	case ArenaEmpty:
		return "arena empty"
	case Panic:
		return "rust panic"
	default:
		return fmt.Sprintf("unknown error code: %d", e)
	}
}

// errFromArenaCode converts a C result from arena try_push / try_pop (AegisErrorCode).
func errFromArenaCode(code C.int32_t) error {
	if code == 0 {
		return nil
	}
	return ErrorCode(code)
}

// recvAlertResult interprets aegis_alert_channel_try_recv return values:
// - n > 0: bytes written to buffer
// - 0: no alert available
// - negative (not an error code): required buffer size
// - NullPointer / Panic: error
func recvAlertResult(code C.int32_t) (n int, need int, err error) {
	if code > 0 {
		return int(code), 0, nil
	}
	if code == 0 {
		return 0, 0, nil
	}
	ec := ErrorCode(code)
	switch ec {
	case NullPointer, Panic:
		return 0, 0, ec
	default:
		// Buffer too small: result is negative required size (see Rust FFI).
		return 0, int(-code), nil
	}
}

// ensureFinalizer registers s for automatic Close unless explicitly closed.
func ensureFinalizer(s *Sensor) {
	runtime.SetFinalizer(s, (*Sensor).finalize)
}

func clearFinalizer(s *Sensor) {
	runtime.SetFinalizer(s, nil)
}

func (s *Sensor) finalize() {
	// Best-effort cleanup if the user forgot to call Close.
	_ = s.closeInternal()
}
