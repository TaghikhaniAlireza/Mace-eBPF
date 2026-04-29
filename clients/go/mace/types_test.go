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

func TestMaceEvent_shadow_fields(t *testing.T) {
	const payload = `{
	  "timestamp": 1,
	  "pid": 2,
	  "uid": 0,
	  "username": "",
	  "process_name": "p",
	  "syscall_name": "mmap",
	  "cmdline": "",
	  "arguments": [],
	  "matched_rules": [],
	  "shadow_matched_rules": ["S1"],
	  "shadow": true
	}`
	var ev MaceEvent
	if err := json.Unmarshal([]byte(payload), &ev); err != nil {
		t.Fatal(err)
	}
	if len(ev.ShadowMatchedRules) != 1 || ev.ShadowMatchedRules[0] != "S1" {
		t.Fatalf("shadow_matched_rules: %+v", ev.ShadowMatchedRules)
	}
	if !ev.Shadow {
		t.Fatal("expected shadow true")
	}
}

func TestMaceEvent_rule_match_metadata(t *testing.T) {
	const payload = `{
	  "timestamp": 1,
	  "pid": 2,
	  "uid": 0,
	  "username": "",
	  "process_name": "p",
	  "syscall_name": "execve",
	  "cmdline": "",
	  "arguments": [],
	  "matched_rules": ["R1"],
	  "matched_rule_metadata": [
	    {
	      "rule_id": "R1",
	      "tags": ["injection"],
	      "mitre_techniques": ["T1574.006"],
	      "references": ["https://example.com"]
	    }
	  ],
	  "shadow_matched_rules": ["S1"],
	  "shadow_rule_metadata": [
	    {
	      "rule_id": "S1",
	      "mitre_tactics": ["Defense Evasion"]
	    }
	  ],
	  "shadow": true
	}`
	var ev MaceEvent
	if err := json.Unmarshal([]byte(payload), &ev); err != nil {
		t.Fatal(err)
	}
	if len(ev.MatchedRuleMetadata) != 1 || ev.MatchedRuleMetadata[0].RuleID != "R1" {
		t.Fatalf("matched_rule_metadata: %+v", ev.MatchedRuleMetadata)
	}
	if len(ev.MatchedRuleMetadata[0].MitreTechniques) != 1 || ev.MatchedRuleMetadata[0].MitreTechniques[0] != "T1574.006" {
		t.Fatalf("mitre_techniques: %+v", ev.MatchedRuleMetadata[0].MitreTechniques)
	}
	if len(ev.ShadowRuleMetadata) != 1 || ev.ShadowRuleMetadata[0].RuleID != "S1" {
		t.Fatalf("shadow_rule_metadata: %+v", ev.ShadowRuleMetadata)
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
