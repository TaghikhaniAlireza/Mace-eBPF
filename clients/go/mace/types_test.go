package mace

import (
	"encoding/json"
	"testing"
)

func TestMaceEvent_JSONRoundTrip_suppressed_by(t *testing.T) {
	const payload = `{
	  "timestamp": 1,
	  "pid": 2,
	  "uid": 1000,
	  "username": "u",
	  "process_name": "p",
	  "syscall_name": "mmap",
	  "cmdline": "",
	  "arguments": [],
	  "matched_rules": ["RULE_A"],
	  "suppressed_by": ["SUPP_X"]
	}`

	var ev MaceEvent
	if err := json.Unmarshal([]byte(payload), &ev); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(ev.MatchedRules) != 1 || ev.MatchedRules[0] != "RULE_A" {
		t.Fatalf("matched_rules: %+v", ev.MatchedRules)
	}
	if len(ev.SuppressedBy) != 1 || ev.SuppressedBy[0] != "SUPP_X" {
		t.Fatalf("suppressed_by: %+v", ev.SuppressedBy)
	}

	out, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var again MaceEvent
	if err := json.Unmarshal(out, &again); err != nil {
		t.Fatalf("round-trip unmarshal: %v", err)
	}
	if len(again.SuppressedBy) != 1 || again.SuppressedBy[0] != "SUPP_X" {
		t.Fatalf("round-trip suppressed_by: %+v", again.SuppressedBy)
	}
}

func TestMaceEvent_omitempty_suppressed_by(t *testing.T) {
	ev := MaceEvent{
		Timestamp:    1,
		PID:          1,
		UID:          0,
		Username:     "",
		ProcessName:  "x",
		SyscallName:  "openat",
		Cmdline:      "",
		Arguments:    nil,
		MatchedRules: []string{"R"},
		SuppressedBy: nil,
	}
	out, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(out, &raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := raw["suppressed_by"]; ok {
		t.Fatalf("expected suppressed_by omitted when empty, got %s", string(out))
	}
}
