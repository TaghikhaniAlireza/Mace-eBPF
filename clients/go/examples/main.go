// Example security monitor: register JSON callback, load YAML rules, start embedded engine.
//
// From `clients/go/examples`, after `cargo build -p aegis-ebpf`:
//
//	export LD_LIBRARY_PATH="/path/to/Aegis-eBPF/target/debug:$LD_LIBRARY_PATH"
//	sudo env PATH="$PATH" LD_LIBRARY_PATH="$LD_LIBRARY_PATH" CGO_ENABLED=1 go run -tags cgo .
//
// By default this loads `tests/simulations/rules.yaml` relative to the **repository root**
// (three levels up from this directory). Override with:
//
//	AEGIS_RULES_FILE=/absolute/path/to/rules.yaml
//
// For a minimal demo only (whoami), set:
//
//	AEGIS_RULES_DEMO=1
//
// In another terminal run `whoami` or `python3 tests/simulations/attack_simulator.py`.
package main

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/aegis-ebpf/sdk/clients/go/aegis"
)

const demoRuleYAML = `rules:
  - id: "TEST_WHOAMI"
    name: "whoami exec"
    severity: "high"
    description: "execve argv contains whoami"
    conditions:
      syscall: "execve"
      argv_contains:
        - "whoami"
`

func loadRulesYAML() (string, string, error) {
	if os.Getenv("AEGIS_RULES_DEMO") == "1" {
		return demoRuleYAML, "(embedded demo TEST_WHOAMI)", nil
	}
	path := os.Getenv("AEGIS_RULES_FILE")
	if path == "" {
		// clients/go/examples -> ../../../tests/simulations/rules.yaml
		path = filepath.Join("..", "..", "..", "tests", "simulations", "rules.yaml")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", "", fmt.Errorf("read rules file %q (resolved %s): %w\nSet AEGIS_RULES_FILE to your rules.yaml, or AEGIS_RULES_DEMO=1 for demo only", path, abs, err)
	}
	return string(data), abs, nil
}

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

	yaml, rulesLabel, err := loadRulesYAML()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := aegis.LoadRules(yaml); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "Loaded rules from %s\n", rulesLabel)

	if err := aegis.StartPipeline(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	fmt.Println("Aegis monitor running. Rules:", rulesLabel)
	fmt.Println("Try: whoami  |  python3 tests/simulations/attack_simulator.py  (from repo root)")
	fmt.Println("Ctrl+C to exit.")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
}
