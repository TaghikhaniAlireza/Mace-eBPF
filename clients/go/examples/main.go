// Example security monitor: [aegis.NewClient] + [aegis.Client.Events] channel, load YAML rules, start embedded engine.
//
// From `clients/go/examples`, after `cargo build -p aegis-ebpf` (links target/debug/libaegis_ebpf.a):
//
//	sudo env PATH="$PATH" CGO_ENABLED=1 go run .
//
// Release Rust + static link: `cargo build --release -p aegis-ebpf` then:
//
//	sudo env PATH="$PATH" CGO_ENABLED=1 go run -tags aegis_static_release .
//
// Production-style default: `/etc/aegis/rules.yaml` when that file exists (override with env).
// Otherwise falls back to repo `tests/simulations/rules.yaml` (three levels up). Override with:
//
//	AEGIS_RULES_FILE=/absolute/path/to/rules.yaml
//
// Optional: AEGIS_LOG_LEVEL=TRACE|INFO|SUPPRESSED|EVENT|ALERT filters Rust [Aegis][LEVEL] lines on stderr
// (see docs/aegis_log_level.md). This example calls SetLogLevel after InitEngine when the env var is set.
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
	"strings"
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

func resolveRulesPath() string {
	if p := os.Getenv("AEGIS_RULES_FILE"); p != "" {
		return p
	}
	const systemDefault = "/etc/aegis/rules.yaml"
	if st, err := os.Stat(systemDefault); err == nil && !st.IsDir() {
		return systemDefault
	}
	return filepath.Join("..", "..", "..", "tests", "simulations", "rules.yaml")
}

func loadRulesForEngine() (rulesLabel string, err error) {
	if os.Getenv("AEGIS_RULES_DEMO") == "1" {
		err = aegis.LoadRules(demoRuleYAML)
		return "(embedded demo TEST_WHOAMI)", err
	}
	path := resolveRulesPath()
	if abs, e := filepath.Abs(path); e == nil {
		rulesLabel = abs
	} else {
		rulesLabel = path
	}
	fi, statErr := os.Stat(path)
	if statErr != nil || fi.IsDir() {
		yaml, _, rerr := loadRulesYAMLFromPath(path)
		if rerr != nil {
			return rulesLabel, rerr
		}
		err = aegis.LoadRules(yaml)
		return rulesLabel, err
	}
	err = aegis.LoadRulesFile(path)
	return rulesLabel, err
}

func loadRulesYAMLFromPath(path string) (yaml string, abs string, err error) {
	abs, err = filepath.Abs(path)
	if err != nil {
		abs = path
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", abs, fmt.Errorf("read rules file %q (resolved %s): %w\nSet AEGIS_RULES_FILE or place rules at /etc/aegis/rules.yaml", path, abs, err)
	}
	return string(data), abs, nil
}

func applyAegisLogLevelFromEnv(s string) error {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "TRACE":
		return aegis.SetLogLevel(aegis.LogLevelTrace)
	case "INFO":
		return aegis.SetLogLevel(aegis.LogLevelInfo)
	case "SUPPRESSED":
		return aegis.SetLogLevel(aegis.LogLevelSuppressed)
	case "EVENT":
		return aegis.SetLogLevel(aegis.LogLevelEvent)
	case "ALERT":
		return aegis.SetLogLevel(aegis.LogLevelAlert)
	default:
		return fmt.Errorf("unknown AEGIS_LOG_LEVEL %q (want TRACE, INFO, SUPPRESSED, EVENT, ALERT)", s)
	}
}

func main() {
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "This example must run as root (CAP_BPF / tracepoint attach).")
		os.Exit(1)
	}

	client, err := aegis.NewClient(256)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer func() { _ = client.Close() }()

	go func() {
		for ev := range client.Events() {
			// Only rows with matched_rules are security alerts unless YAML suppressions cleared the alert path.
			// Observations with matched_rules=[] are normal syscall telemetry (not an "ALERT").
			label := "EVENT"
			switch {
			case len(ev.MatchedRules) > 0 && len(ev.SuppressedBy) == 0:
				label = "ALERT"
			case len(ev.MatchedRules) > 0 && len(ev.SuppressedBy) > 0:
				label = "SUPPRESSED_ALERT"
			case len(ev.SuppressedBy) > 0:
				label = "SUPPRESSED"
			}
			fmt.Printf("%s matched=%v suppressed_by=%v syscall=%s pid=%d uid=%d user=%q comm=%q cmdline=%q args=%v ts=%d\n",
				label, ev.MatchedRules, ev.SuppressedBy, ev.SyscallName, ev.PID, ev.UID, ev.Username, ev.ProcessName, ev.Cmdline, ev.Arguments, ev.Timestamp)
		}
	}()

	if err := aegis.InitEngine(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if lvl := os.Getenv("AEGIS_LOG_LEVEL"); lvl != "" {
		if err := applyAegisLogLevelFromEnv(lvl); err != nil {
			fmt.Fprintf(os.Stderr, "AEGIS_LOG_LEVEL: %v\n", err)
		}
	}
	defer func() { _ = aegis.StopPipeline() }()

	rulesLabel, err := loadRulesForEngine()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "Loaded rules from %s\n", rulesLabel)

	if err := aegis.StartPipeline(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	fmt.Println("Aegis monitor running. Rules:", rulesLabel)
	fmt.Println("Stdout labels (ALERT / EVENT / SUPPRESSED_*): from Client.Events() — not filtered by AEGIS_LOG_LEVEL.")
	fmt.Println("Stderr [Aegis][LEVEL] lines: filtered by AEGIS_LOG_LEVEL — see docs/aegis_log_level.md")
	fmt.Println("Try: whoami  |  python3 tests/simulations/attack_simulator.py  (from repo root)")
	fmt.Println("Ctrl+C to exit.")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
}
