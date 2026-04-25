package aegis

/*
#include "aegis.h"
#include <stdlib.h>
*/
import "C"

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"unsafe"
)

// ErrAlertChannelClosed is returned when calling methods on a closed AlertChannelHandle.
var ErrAlertChannelClosed = errors.New("aegis: alert channel closed")

// AlertChannelHandle is a low-level CGO wrapper for the protobuf alert queue (no poller goroutine).
type AlertChannelHandle struct {
	mu       sync.RWMutex
	h        *C.AegisAlertChannelHandle
	freeOnce sync.Once
}

// NewAlertChannelHandle creates a bounded alert channel in Rust.
func NewAlertChannelHandle(capacity int) (*AlertChannelHandle, error) {
	if capacity <= 0 {
		return nil, fmt.Errorf("aegis: alert channel capacity must be > 0")
	}
	h := C.aegis_alert_channel_new(C.size_t(capacity))
	if h == nil {
		return nil, fmt.Errorf("aegis: aegis_alert_channel_new failed")
	}
	ch := &AlertChannelHandle{h: h}
	runtime.SetFinalizer(ch, (*AlertChannelHandle).finalize)
	return ch, nil
}

func (c *AlertChannelHandle) finalize() {
	defer func() { _ = recover() }()
	c.Close()
}

// Close frees the native handle; idempotent.
func (c *AlertChannelHandle) Close() {
	c.freeOnce.Do(func() {
		runtime.SetFinalizer(c, nil)
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.h != nil {
			C.aegis_alert_channel_free(c.h)
			c.h = nil
		}
	})
}

// TryRecvNonBlocking mirrors the Rust try_recv FFI (returns n, need, err from recvAlertResult).
func (c *AlertChannelHandle) TryRecvNonBlocking(buf []byte) (n int, need int, err error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.h == nil {
		return 0, 0, ErrAlertChannelClosed
	}
	if len(buf) == 0 {
		return 0, 0, fmt.Errorf("aegis: empty buffer")
	}
	return recvAlertResult(C.aegis_alert_channel_try_recv(
		c.h,
		(*C.uint8_t)(unsafe.Pointer(&buf[0])),
		C.size_t(len(buf)),
	))
}
