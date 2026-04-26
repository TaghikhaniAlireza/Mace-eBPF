package aegis

// StandardizedEvent mirrors the JSON emitted by Rust's pipeline
// (serde_json of `aegis_ebpf::StandardizedEvent`).
type StandardizedEvent struct {
	Timestamp    uint64   `json:"timestamp"`
	PID          uint32   `json:"pid"`
	ProcessName  string   `json:"process_name"`
	SyscallName  string   `json:"syscall_name"`
	Arguments    []string `json:"arguments"`
	MatchedRules []string `json:"matched_rules"`
}
