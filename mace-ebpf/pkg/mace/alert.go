package mace

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/mace-ebpf/sdk/pkg/mace/maceproto"
)

// Severity matches maceproto.Severity for the public Go API.
type Severity int32

const (
	SeverityUnspecified Severity = 0
	SeverityInfo        Severity = 1
	SeverityLow         Severity = 2
	SeverityMedium      Severity = 3
	SeverityHigh        Severity = 4
	SeverityCritical    Severity = 5
)

// String returns a short name for logging.
func (s Severity) String() string {
	switch s {
	case SeverityUnspecified:
		return "UNSPECIFIED"
	case SeverityInfo:
		return "INFO"
	case SeverityLow:
		return "LOW"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityHigh:
		return "HIGH"
	case SeverityCritical:
		return "CRITICAL"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", s)
	}
}

// Alert is a decoded protobuf alert with convenient Go fields.
type Alert struct {
	AlertID     string
	RuleName    string
	Severity    Severity
	Message     string
	TGID        uint32
	ProcessName string
	Timestamp   time.Time
	ContextJSON string
}

func alertFromProto(a *maceproto.Alert) Alert {
	if a == nil {
		return Alert{}
	}
	ts := time.Unix(0, int64(a.TimestampNs))
	return Alert{
		AlertID:     a.AlertId,
		RuleName:    a.RuleName,
		Severity:    Severity(a.Severity),
		Message:     a.Message,
		TGID:        a.Tgid,
		ProcessName: a.ProcessName,
		Timestamp:   ts,
		ContextJSON: a.ContextJson,
	}
}

// ContextMap parses ContextJSON as a generic JSON object (object only).
func (a *Alert) ContextMap() (map[string]string, error) {
	if a.ContextJSON == "" {
		return map[string]string{}, nil
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(a.ContextJSON), &raw); err != nil {
		return nil, err
	}
	out := make(map[string]string, len(raw))
	for k, v := range raw {
		// encode values as compact JSON strings
		out[k] = string(v)
	}
	return out, nil
}
