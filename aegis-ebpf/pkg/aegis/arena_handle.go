package aegis

/*
#include "aegis.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
)

// ErrArenaClosed is returned when calling methods on a closed Arena.
var ErrArenaClosed = errors.New("aegis: arena closed")

// Arena is a low-level CGO wrapper around Rust's event ring buffer (no background goroutines).
// Prefer explicit Close(); a runtime finalizer runs best-effort cleanup if Close was forgotten.
type Arena struct {
	mu sync.RWMutex
	h  *C.AegisArenaHandle
	// once ensures aegis_arena_free runs at most once (explicit Close vs finalizer).
	freeOnce sync.Once
}

// NewArena creates an arena with capacity (must be a positive power of two).
func NewArena(capacity int) (*Arena, error) {
	if capacity <= 0 || (capacity&(capacity-1)) != 0 {
		return nil, fmt.Errorf("aegis: arena capacity must be a positive power of two, got %d", capacity)
	}
	h := C.aegis_arena_new(C.size_t(capacity))
	if h == nil {
		return nil, fmt.Errorf("aegis: aegis_arena_new failed")
	}
	a := &Arena{h: h}
	runtime.SetFinalizer(a, (*Arena).finalize)
	return a, nil
}

func (a *Arena) finalize() {
	// Do not panic across the CGO boundary; Close is idempotent.
	defer func() { _ = recover() }()
	a.Close()
}

// Close frees the native arena handle. Safe to call multiple times and from a finalizer.
func (a *Arena) Close() {
	a.freeOnce.Do(func() {
		runtime.SetFinalizer(a, nil)
		a.mu.Lock()
		defer a.mu.Unlock()
		if a.h != nil {
			C.aegis_arena_free(a.h)
			a.h = nil
		}
	})
}

// TryPush enqueues one event (non-blocking); returns ArenaFull when the ring is full.
func (a *Arena) TryPush(e Event) error {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.h == nil {
		return ErrArenaClosed
	}
	ce := e.toCEvent()
	return errFromArenaCode(C.aegis_arena_try_push(a.h, &ce))
}

// TryPop removes one event (non-blocking); returns (Event{}, ArenaEmpty) when empty.
func (a *Arena) TryPop() (Event, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.h == nil {
		return Event{}, ErrArenaClosed
	}
	var ce C.RawMemoryEvent
	switch code := ErrorCode(C.aegis_arena_try_pop(a.h, &ce)); code {
	case Success:
		return fromCEvent(&ce), nil
	case ArenaEmpty:
		return Event{}, ArenaEmpty
	default:
		return Event{}, code
	}
}
