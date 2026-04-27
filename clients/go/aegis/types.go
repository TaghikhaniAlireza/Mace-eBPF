package aegis

// StandardizedEvent mirrors the JSON emitted by Rust's pipeline
// (serde_json of `aegis_ebpf::StandardizedEvent`).
type StandardizedEvent struct {
	Timestamp    uint64   `json:"timestamp"`
	PID          uint32   `json:"pid"`
	UID          uint32   `json:"uid"`
	Username     string   `json:"username"`
	ProcessName  string   `json:"process_name"`
	SyscallName  string   `json:"syscall_name"`
	Cmdline      string   `json:"cmdline"`
	Arguments    []string `json:"arguments"`
	MatchedRules []string `json:"matched_rules"`
	// SuppressedBy lists suppression entry ids when alerts were suppressed (matched_rules still populated).
	SuppressedBy []string `json:"suppressed_by,omitempty"`
}
