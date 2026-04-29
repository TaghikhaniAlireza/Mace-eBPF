package mace_test

import (
	"testing"
	"time"

	"github.com/mace-ebpf/sdk/pkg/mace"
)

// TestHighThroughputJitStorm runs Rust's scoped JIT-storm simulator (100k events) and asserts
// all events are accounted for (no silent loss). Throughput is logged for CI / local profiling.
func TestHighThroughputJitStorm(t *testing.T) {
	const count uint32 = 100_000

	a, err := mace.NewArena(65536)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	stats, elapsed, err := a.SimulateJitStormDuration(count)
	if err != nil {
		t.Fatalf("SimulateJitStorm: %v", err)
	}
	if stats.Requested != uint64(count) {
		t.Fatalf("requested: want %d got %d", count, stats.Requested)
	}
	if stats.Pushed != stats.Popped || stats.Pushed != stats.Requested {
		t.Fatalf("mismatch pushed=%d popped=%d requested=%d full_retries=%d",
			stats.Pushed, stats.Popped, stats.Requested, stats.FullRetries)
	}

	sec := elapsed.Seconds()
	if sec <= 0 {
		sec = 1e-9
	}
	eps := float64(stats.Popped) / sec
	t.Logf("jit_storm: %d events in %v (%.0f events/s), full_retries=%d",
		stats.Popped, elapsed, eps, stats.FullRetries)

	// Sanity bound: 100k ring ops should complete quickly on CI hardware (tunable if flaky).
	if elapsed > 30*time.Second {
		t.Fatalf("storm took too long: %v", elapsed)
	}
}

// TestHighThroughputJitStormSmallerArena runs the same Rust-side storm with a smaller ring.
//
// Do **not** call TryPop/TryPush on this arena from another goroutine while SimulateJitStorm runs:
// the Rust simulator is SPSC (one internal producer, one internal consumer) and its completion
// is based on an internal pop count. External pops steal events without updating that count, so
// the Rust consumer can spin forever (until the 10m Go test timeout).
func TestHighThroughputJitStormSmallerArena(t *testing.T) {
	const count uint32 = 50_000

	a, err := mace.NewArena(32768)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	stats, elapsed, err := a.SimulateJitStormDuration(count)
	if err != nil {
		t.Fatalf("SimulateJitStorm: %v", err)
	}
	if stats.Pushed != stats.Requested || stats.Popped != stats.Requested {
		t.Fatalf("counts pushed=%d popped=%d requested=%d", stats.Pushed, stats.Popped, stats.Requested)
	}
	t.Logf("jit_storm (32k cap): %v, full_retries=%d", elapsed, stats.FullRetries)
}
