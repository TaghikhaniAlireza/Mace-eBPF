package aegis_test

import (
	"runtime"
	"testing"
	"time"

	"github.com/aegis-ebpf/sdk/pkg/aegis"
)

// TestCGOBoundaryAndGCStress exercises Arena create / push / Close in a tight loop with
// aggressive GC to catch double-free or use-after-free at the cgo boundary.
func TestCGOBoundaryAndGCStress(t *testing.T) {
	const iterations = 10_000
	ev := aegis.Event{
		TGID:        1,
		PID:         2,
		TimestampNs: uint64(time.Now().UnixNano()),
		SyscallID:   aegis.SyscallMmap,
		Args:        [6]uint64{1, 2, 3, 4, 5, 6},
		CgroupID:    7,
		Comm:        [16]byte{'g', 'c', 0},
	}

	for i := 0; i < iterations; i++ {
		a, err := aegis.NewArena(16)
		if err != nil {
			t.Fatalf("iteration %d NewArena: %v", i, err)
		}
		if err := a.TryPush(ev); err != nil {
			t.Fatalf("iteration %d TryPush: %v", i, err)
		}
		a.Close()
		if i%100 == 0 {
			runtime.GC()
		}
	}
	runtime.GC()
	runtime.GC()
}

func TestAlertChannelHandleGCStress(t *testing.T) {
	const iterations = 5_000
	for i := 0; i < iterations; i++ {
		ch, err := aegis.NewAlertChannelHandle(64)
		if err != nil {
			t.Fatalf("iteration %d NewAlertChannelHandle: %v", i, err)
		}
		buf := make([]byte, 256)
		_, _, _ = ch.TryRecvNonBlocking(buf)
		ch.Close()
		if i%100 == 0 {
			runtime.GC()
		}
	}
	runtime.GC()
}
