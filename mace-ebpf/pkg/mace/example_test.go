package mace_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/mace-ebpf/sdk/pkg/mace"
)

func TestSensorLifecycle(t *testing.T) {
	cfg := mace.DefaultConfig()
	sensor, err := mace.NewSensor(cfg)
	if err != nil {
		t.Fatalf("NewSensor: %v", err)
	}
	defer func() {
		if err := sensor.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
	}()

	if sensor == nil {
		t.Fatal("sensor is nil")
	}
}

func TestEventPushPop(t *testing.T) {
	cfg := mace.DefaultConfig()
	sensor, err := mace.NewSensor(cfg)
	if err != nil {
		t.Fatalf("NewSensor: %v", err)
	}
	defer sensor.Close()

	testEvent := mace.Event{
		TGID:        1234,
		PID:         5678,
		TimestampNs: uint64(time.Now().UnixNano()),
		SyscallID:   mace.SyscallMmap,
		Args:        [6]uint64{0xDEADBEEF, 64, 0, 0, 0, 0},
		CgroupID:    1234,
	}
	copy(testEvent.Comm[:], []byte("test"))

	if err := sensor.PushEvent(testEvent); err != nil {
		t.Fatalf("PushEvent: %v", err)
	}

	select {
	case ev := <-sensor.Events():
		if ev.TGID != testEvent.TGID {
			t.Errorf("TGID: want %d, got %d", testEvent.TGID, ev.TGID)
		}
		if ev.Args[0] != testEvent.Args[0] {
			t.Errorf("Args[0]: want 0x%x, got 0x%x", testEvent.Args[0], ev.Args[0])
		}
		if ev.CommString() != "test" {
			t.Errorf("comm: want test, got %q", ev.CommString())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for event")
	}
}

func TestMultipleEvents(t *testing.T) {
	cfg := mace.DefaultConfig()
	sensor, err := mace.NewSensor(cfg)
	if err != nil {
		t.Fatalf("NewSensor: %v", err)
	}
	defer sensor.Close()

	const numEvents = 10
	for i := 0; i < numEvents; i++ {
		ev := mace.Event{
			TGID:        uint32(1000 + i),
			PID:         uint32(2000 + i),
			TimestampNs: uint64(time.Now().UnixNano()),
			SyscallID:   mace.SyscallMmap,
			Args:        [6]uint64{uint64(0x1000 + i*0x100), 64},
		}
		if err := sensor.PushEvent(ev); err != nil {
			t.Fatalf("PushEvent %d: %v", i, err)
		}
	}

	received := 0
	deadline := time.After(3 * time.Second)
	for received < numEvents {
		select {
		case ev := <-sensor.Events():
			t.Logf("event tgid=%d addr=0x%x", ev.TGID, ev.Args[0])
			received++
		case <-deadline:
			t.Fatalf("timeout: got %d/%d events", received, numEvents)
		}
	}
}

func ExampleSensor() {
	cfg := mace.DefaultConfig()
	sensor, err := mace.NewSensor(cfg)
	if err != nil {
		panic(err)
	}
	defer sensor.Close()

	go func() {
		for event := range sensor.Events() {
			fmt.Printf("Event: PID=%d, arg0=0x%x\n", event.PID, event.Args[0])
		}
	}()

	go func() {
		for alert := range sensor.Alerts() {
			fmt.Printf("Alert: [%s] %s - %s\n", alert.Severity, alert.RuleName, alert.Message)
		}
	}()

	time.Sleep(100 * time.Millisecond)
}
