package mace

/*
#include "mace.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"time"
)

// ErrArenaClosed is returned when calling methods on a closed Arena.
var ErrArenaClosed = errors.New("mace: arena closed")

// JitStormStats mirrors C `JitStormStats` / Rust `ffi::jit_storm::JitStormStats` (repr C, u64 fields).
type JitStormStats struct {
	Requested   uint64
	Pushed      uint64
	Popped      uint64
	FullRetries uint64
}

// Arena is a low-level CGO wrapper around Rust's event ring buffer (no background goroutines).
// Prefer explicit Close(); a runtime finalizer runs best-effort cleanup if Close was forgotten.
type Arena struct {
	mu sync.RWMutex
	h  *C.MaceArenaHandle
	// once ensures mace_arena_free runs at most once (explicit Close vs finalizer).
	freeOnce sync.Once
}

// NewArena creates an arena with capacity (must be a positive power of two).
func NewArena(capacity int) (*Arena, error) {
	if capacity <= 0 || (capacity&(capacity-1)) != 0 {
		return nil, fmt.Errorf("mace: arena capacity must be a positive power of two, got %d", capacity)
	}
	h := C.mace_arena_new(C.size_t(capacity))
	if h == nil {
		return nil, fmt.Errorf("mace: mace_arena_new failed")
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
			C.mace_arena_free(a.h)
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
	return errFromArenaCode(C.mace_arena_try_push(a.h, &ce))
}

// TryPop removes one event (non-blocking); returns (Event{}, ArenaEmpty) when empty.
func (a *Arena) TryPop() (Event, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.h == nil {
		return Event{}, ErrArenaClosed
	}
	var ce C.RawMemoryEvent
	switch code := ErrorCode(C.mace_arena_try_pop(a.h, &ce)); code {
	case Success:
		return fromCEvent(&ce), nil
	case ArenaEmpty:
		return Event{}, ArenaEmpty
	default:
		return Event{}, code
	}
}

// SimulateJitStorm runs Rust's scoped high-throughput producer/consumer on this arena (Phase 4.1).
// `count` events are moved through the ring; see returned stats for push/pop counts and full retries.
func (a *Arena) SimulateJitStorm(count uint32) (JitStormStats, error) {
	var h *C.MaceArenaHandle
	a.mu.RLock()
	if a.h == nil {
		a.mu.RUnlock()
		return JitStormStats{}, ErrArenaClosed
	}
	h = a.h
	a.mu.RUnlock()

	var cstats C.JitStormStats
	rc := C.mace_simulate_jit_storm(h, C.uint32_t(count), &cstats)
	if err := errFromArenaCode(rc); err != nil {
		return JitStormStats{}, err
	}
	return JitStormStats{
		Requested:   uint64(cstats.requested),
		Pushed:      uint64(cstats.pushed),
		Popped:      uint64(cstats.popped),
		FullRetries: uint64(cstats.full_retries),
	}, nil
}

// SimulateJitStormDuration is like SimulateJitStorm but also returns elapsed wall time (for throughput tests).
func (a *Arena) SimulateJitStormDuration(count uint32) (stats JitStormStats, d time.Duration, err error) {
	start := time.Now()
	stats, err = a.SimulateJitStorm(count)
	d = time.Since(start)
	return stats, d, err
}
