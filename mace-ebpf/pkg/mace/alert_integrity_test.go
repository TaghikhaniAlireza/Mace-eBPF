package mace_test

import (
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/mace-ebpf/sdk/pkg/mace"
	"github.com/mace-ebpf/sdk/pkg/mace/maceproto"
)

// TestProtobufAlertIntegrity pushes a maximal-field alert from Rust and unmarshals in Go
// to verify wire compatibility and no corruption across the CGO boundary.
func TestProtobufAlertIntegrity(t *testing.T) {
	ch, err := mace.NewAlertChannelHandle(8)
	if err != nil {
		t.Fatal(err)
	}
	defer ch.Close()

	if err := ch.FeedTestAlert(); err != nil {
		t.Fatalf("FeedTestAlert: %v", err)
	}

	buf := make([]byte, 512*1024)
	n, need, recvErr := ch.TryRecvNonBlocking(buf)
	if recvErr != nil {
		t.Fatalf("TryRecvNonBlocking: %v", recvErr)
	}
	if need > len(buf) {
		t.Fatalf("buffer too small: need=%d", need)
	}
	if n <= 0 {
		t.Fatal("expected non-empty protobuf payload")
	}

	var got maceproto.Alert
	if err := proto.Unmarshal(buf[:n], &got); err != nil {
		t.Fatalf("proto.Unmarshal: %v", err)
	}

	wantID := "edgecase-alert-id-12345"
	if got.AlertId != wantID {
		t.Fatalf("alert_id: want %q got %q", wantID, got.AlertId)
	}
	if got.RuleName != "rule-integrity-αβ" {
		t.Fatalf("rule_name: got %q", got.RuleName)
	}
	if got.Severity != maceproto.Severity_SEVERITY_CRITICAL {
		t.Fatalf("severity: want CRITICAL got %v", got.Severity)
	}
	if got.Tgid != ^uint32(0) { // u32::MAX
		t.Fatalf("tgid: want %d got %d", ^uint32(0), got.Tgid)
	}
	const u64max uint64 = 18446744073709551615
	if got.TimestampNs != u64max {
		t.Fatalf("timestamp_ns: want %d got %d", u64max, got.TimestampNs)
	}
	if got.ProcessName != "procname-no-nul-padding" {
		t.Fatalf("process_name: got %q (must not gain NUL padding)", got.ProcessName)
	}
	if strings.IndexByte(got.ProcessName, 0) >= 0 {
		t.Fatal("process_name must not contain embedded NUL")
	}
	if !strings.Contains(got.Message, "escaped") {
		t.Fatalf("message field corrupted: %q", got.Message)
	}
	if !strings.Contains(got.ContextJson, `"big"`) || !strings.Contains(got.ContextJson, "ZZ") {
		t.Fatalf("context_json missing expected nested payload prefix")
	}
}
