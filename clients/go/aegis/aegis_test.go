package aegis

import (
	"encoding/json"
	"testing"
	"time"
)

// Tests require CGO and libaegis_ebpf.a (build with `cargo build -p aegis-ebpf` from repo root).

func TestSetLogLevel_allValidLevels(t *testing.T) {
	for _, lvl := range []LogLevel{
		LogLevelTrace,
		LogLevelInfo,
		LogLevelSuppressed,
		LogLevelEvent,
		LogLevelAlert,
	} {
		if err := SetLogLevel(lvl); err != nil {
			t.Fatalf("SetLogLevel(%d): %v", lvl, err)
		}
	}
}

func TestSetLogLevel_invalid(t *testing.T) {
	if err := SetLogLevel(5); err == nil {
		t.Fatal("expected error for level 5")
	}
	if err := SetLogLevel(-1); err == nil {
		t.Fatal("expected error for level -1")
	}
}

func TestInitEngineWithConfig_logLevel(t *testing.T) {
	alert := LogLevelAlert
	if err := InitEngineWithConfig(EngineConfig{LogLevel: &alert}); err != nil {
		t.Fatalf("InitEngineWithConfig: %v", err)
	}
	_ = SetLogLevel(LogLevelTrace)
}

func TestInitEngineWithConfig_nilLogLevel(t *testing.T) {
	if err := InitEngineWithConfig(EngineConfig{}); err != nil {
		t.Fatalf("InitEngineWithConfig empty: %v", err)
	}
}

func TestNewClient_duplicateFails(t *testing.T) {
	c1, err := NewClient(4)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewClient(4); err == nil {
		t.Fatal("expected error when client already active")
	}
	if err := c1.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestClient_Close_invalid(t *testing.T) {
	c, err := NewClient(2)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err == nil {
		t.Fatal("expected error on second Close")
	}
}

func TestClient_Events_channelReceivesDecodedJSON(t *testing.T) {
	const payload = `{
	  "timestamp": 99,
	  "pid": 2,
	  "uid": 1000,
	  "username": "alice",
	  "process_name": "demo",
	  "syscall_name": "mmap",
	  "cmdline": "/bin/demo",
	  "arguments": ["addr=0x1","len=0x2"],
	  "matched_rules": ["RULE_A"],
	  "suppressed_by": ["SUPP_X"]
	}`

	c, err := NewClient(8)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()

	done := make(chan struct{})
	go func() {
		pushAegisEventJSON(payload)
		close(done)
	}()

	select {
	case ev := <-c.Events():
		if ev.Timestamp != 99 || ev.PID != 2 || ev.UID != 1000 {
			t.Fatalf("fields: %+v", ev)
		}
		if ev.Username != "alice" || ev.ProcessName != "demo" || ev.SyscallName != "mmap" {
			t.Fatalf("identity: %+v", ev)
		}
		if ev.Cmdline != "/bin/demo" || len(ev.Arguments) != 2 {
			t.Fatalf("cmdline/args: %+v", ev)
		}
		if len(ev.MatchedRules) != 1 || ev.MatchedRules[0] != "RULE_A" {
			t.Fatalf("matched_rules: %+v", ev.MatchedRules)
		}
		if len(ev.SuppressedBy) != 1 || ev.SuppressedBy[0] != "SUPP_X" {
			t.Fatalf("suppressed_by: %+v", ev.SuppressedBy)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for event on channel")
	}
	<-done
}

func TestClient_Events_channelClosedAfterClose(t *testing.T) {
	c, err := NewClient(2)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case _, ok := <-c.Events():
		if ok {
			t.Fatal("expected channel closed after Close")
		}
	case <-time.After(time.Second):
		t.Fatal("timeout reading closed channel")
	}
}

func TestClient_defaultBufferSize(t *testing.T) {
	c, err := NewClient(0)
	if err != nil {
		t.Fatal(err)
	}
	// defaultEventBuffer — send without blocking up to that many (simulate burst)
	for i := 0; i < 10; i++ {
		b, _ := json.Marshal(AegisEvent{Timestamp: uint64(i), ProcessName: "x", SyscallName: "mmap"})
		pushAegisEventJSON(string(b))
	}
	for i := 0; i < 10; i++ {
		ev := <-c.Events()
		if ev.Timestamp != uint64(i) {
			t.Fatalf("want ts %d got %d", i, ev.Timestamp)
		}
	}
	_ = c.Close()
}
