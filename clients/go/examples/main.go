// Example security monitor: register JSON callback, load execve rule for whoami, start embedded engine.
//
// From the repository root, after `cargo build -p aegis-ebpf`:
//
//	cd clients/go/examples
//	sudo env PATH="$PATH" CGO_ENABLED=1 go run -tags cgo .
//
// CGO links via #cgo LDFLAGS to ../../../target/debug; if the runtime loader cannot find libaegis_ebpf.so, set:
//
//	export LD_LIBRARY_PATH="/path/to/Aegis-eBPF/target/debug:$LD_LIBRARY_PATH"
//
// In another terminal run `whoami`; this process prints alert lines (uid, cmdline, matched rules).
package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/aegis-ebpf/sdk/clients/go/aegis"
)

const ruleYAML = `rules:
  - id: "TEST_WHOAMI"
    name: "whoami exec"
    severity: "high"
    description: "execve argv contains whoami"
    conditions:
      syscall: "execve"
      argv_contains:
        - "whoami"
`

func main() {
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "This example must run as root (CAP_BPF / tracepoint attach).")
		os.Exit(1)
	}

	if err := aegis.RegisterEventCallback(func(ev aegis.StandardizedEvent) {
		fmt.Printf("ALERT rules=%v syscall=%s pid=%d uid=%d user=%q comm=%q cmdline=%q args=%v ts=%d\n",
			ev.MatchedRules, ev.SyscallName, ev.PID, ev.UID, ev.Username, ev.ProcessName, ev.Cmdline, ev.Arguments, ev.Timestamp)
	}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer aegis.UnregisterEventCallback()

	if err := aegis.InitEngine(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer func() { _ = aegis.StopPipeline() }()

	if err := aegis.LoadRules(ruleYAML); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if err := aegis.StartPipeline(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	fmt.Println("Aegis monitor running. In another shell run: whoami")
	fmt.Println("Ctrl+C to exit.")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
}
