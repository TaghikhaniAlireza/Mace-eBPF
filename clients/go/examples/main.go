// Example: register JSON event callback and keep the process alive.
//
// Build the Rust cdylib first from the repo root:
//
//	cargo build -p aegis-ebpf
//
// Then run (from repo root or this directory):
//
//	CGO_ENABLED=1 go run -tags cgo .
package main

import (
	"fmt"
	"os"

	"github.com/aegis-ebpf/sdk/clients/go/aegis"
)

func main() {
	if err := aegis.RegisterEventCallback(func(ev aegis.StandardizedEvent) {
		fmt.Printf("Alert: rules=%v syscall=%s pid=%d process=%q args=%v ts=%d\n",
			ev.MatchedRules, ev.SyscallName, ev.PID, ev.ProcessName, ev.Arguments, ev.Timestamp)
	}); err != nil {
		fmt.Fprintf(os.Stderr, "register: %v\n", err)
		os.Exit(1)
	}
	defer aegis.UnregisterEventCallback()

	fmt.Println("Callback registered. JSON events will arrive when the Rust pipeline invokes the C callback.")
	fmt.Println("Run the Aegis sensor / pipeline (Rust binary) in another process to drive events.")
	fmt.Println("Blocking forever — Ctrl+C to exit.")

	// Keep the runtime alive for async C→Go callbacks.
	select {}
}
