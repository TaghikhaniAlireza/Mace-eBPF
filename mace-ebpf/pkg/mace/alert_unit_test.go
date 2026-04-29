package mace

import (
	"testing"

	"github.com/mace-ebpf/sdk/pkg/mace/maceproto"
)

func TestAlertFromProto(t *testing.T) {
	ts := uint64(1_700_000_000_000_000_000)
	a := alertFromProto(&maceproto.Alert{
		AlertId:     "id-1",
		RuleName:    "rule-a",
		Severity:    maceproto.Severity_SEVERITY_CRITICAL,
		Message:     "msg",
		Tgid:        99,
		ProcessName: "proc",
		TimestampNs: ts,
		ContextJson: `{"k":"v"}`,
	})

	if a.AlertID != "id-1" || a.RuleName != "rule-a" {
		t.Fatalf("unexpected alert: %+v", a)
	}
	if a.Severity != SeverityCritical {
		t.Fatalf("severity: got %v", a.Severity)
	}
	if a.Timestamp.UnixNano() != int64(ts) {
		t.Fatalf("time: got %v", a.Timestamp)
	}

	m, err := a.ContextMap()
	if err != nil {
		t.Fatal(err)
	}
	if m["k"] != `"v"` {
		t.Fatalf("context map: %+v", m)
	}
}
