// Command mace-agent is the standalone Mace eBPF security agent (systemd-friendly).
package main

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/mace-ebpf/sdk/clients/go/internal/agentconfig"
	"github.com/mace-ebpf/sdk/clients/go/mace"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "mace-agent: %v\n", err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	var configPath string
	root := &cobra.Command{
		Use:   "mace-agent",
		Short: "Mace eBPF security agent",
	}
	root.PersistentFlags().StringVarP(&configPath, "config", "c", "", "path to configuration file")

	run := &cobra.Command{
		Use:   "run",
		Short: "Run the agent (default if no subcommand)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if configPath == "" {
				return fmt.Errorf("--config is required")
			}
			return runAgent(configPath)
		},
	}
	run.Flags().StringVarP(&configPath, "config", "c", "", "path to configuration file (required)")
	_ = run.MarkFlagRequired("config")

	status := &cobra.Command{
		Use:   "status",
		Short: "Print engine health JSON (requires same --config as the running agent for rules path context)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if configPath == "" {
				return fmt.Errorf("--config is required")
			}
			return runStatus(configPath)
		},
	}
	status.Flags().StringVarP(&configPath, "config", "c", "", "path to configuration file (required)")
	_ = status.MarkFlagRequired("config")

	root.AddCommand(run, status)
	root.RunE = func(cmd *cobra.Command, args []string) error {
		if configPath == "" {
			return cmd.Help()
		}
		return runAgent(configPath)
	}
	return root
}

func prepareAuditEnv(path string) {
	p := strings.TrimSpace(path)
	if p == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
		fmt.Fprintf(os.Stderr, "mace-agent: audit log disabled (cannot create %q parent: %v)\n", p, err)
		return
	}
	_ = os.Setenv("MACE_AUDIT_LOG_PATH", p)
}

func runStatus(configPath string) error {
	cfg, err := agentconfig.Load(configPath)
	if err != nil {
		return err
	}
	prepareAuditEnv(cfg.Audit.Path)
	if err := mace.InitEngine(); err != nil {
		return fmt.Errorf("init engine: %w", err)
	}
	if _, err := os.Stat(cfg.Rules.Path); err != nil {
		fmt.Fprintf(os.Stderr, "mace-agent status: warning: rules path %q not readable: %v\n", cfg.Rules.Path, err)
	} else if err := mace.LoadRulesFile(cfg.Rules.Path); err != nil {
		fmt.Fprintf(os.Stderr, "mace-agent status: warning: could not load rules %q: %v (health.rule_count may be 0)\n", cfg.Rules.Path, err)
	}
	buf := make([]byte, 8192)
	s, err := mace.EngineHealthJSON(buf)
	if err != nil {
		return err
	}
	fmt.Println(s)
	return nil
}

func runAgent(configPath string) error {
	cfg, err := agentconfig.Load(configPath)
	if err != nil {
		return err
	}

	prepareAuditEnv(cfg.Audit.Path)

	if err := os.MkdirAll(filepath.Dir(cfg.Logging.Path), 0755); err != nil {
		return fmt.Errorf("create log directory: %w", err)
	}
	logFile, err := os.OpenFile(cfg.Logging.Path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("open event log %q: %w", cfg.Logging.Path, err)
	}
	defer logFile.Close()

	eventLog := logrus.New()
	eventLog.SetOutput(logFile)
	eventLog.SetLevel(logrus.InfoLevel)
	if cfg.Logging.Format == "json" {
		eventLog.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: "2006-01-02T15:04:05.000000000Z07:00",
		})
	} else {
		eventLog.SetFormatter(&logrus.TextFormatter{
			FullTimestamp:   true,
			TimestampFormat: "2006-01-02T15:04:05",
			DisableColors:   true,
		})
	}

	fmt.Fprintf(os.Stderr, "mace-agent: logging security events to %s (format=%s)\n", cfg.Logging.Path, cfg.Logging.Format)
	if p := strings.TrimSpace(cfg.Audit.Path); p != "" {
		fmt.Fprintf(os.Stderr, "mace-agent: audit log enabled at %s (MACE_AUDIT_LOG_PATH)\n", p)
	}

	client, err := mace.NewClient(4096)
	if err != nil {
		return fmt.Errorf("mace client: %w", err)
	}

	shutdown := make(chan struct{})
	go func() {
		for ev := range client.Events() {
			logSecurityEvent(eventLog, &ev, cfg.Logging.Format)
		}
		close(shutdown)
	}()

	if err := mace.InitEngine(); err != nil {
		_ = client.Close()
		return fmt.Errorf("init engine: %w", err)
	}

	if err := mace.LoadRulesFile(cfg.Rules.Path); err != nil {
		_ = client.Close()
		return fmt.Errorf("load rules %q: %w", cfg.Rules.Path, err)
	}

	if err := mace.StartPipeline(); err != nil {
		_ = client.Close()
		return fmt.Errorf("start pipeline: %w", err)
	}

	fmt.Fprintf(os.Stderr, "mace-agent: engine running (rules=%q); send SIGTERM or SIGINT to stop\n", cfg.Rules.Path)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	signal.Stop(sigCh)

	fmt.Fprintln(os.Stderr, "mace-agent: shutdown signal received, stopping Mace engine...")
	_ = mace.StopPipeline()
	if err := client.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "mace-agent: client close: %v\n", err)
	}
	<-shutdown
	fmt.Fprintln(os.Stderr, "mace-agent: stopped cleanly")
	return nil
}

func logSecurityEvent(log *logrus.Logger, ev *mace.MaceEvent, format string) {
	// Quiet default: only log high-signal syscalls or anything that matched a rule / shadow rule.
	// Exec / execveat are always logged so operators retain a full command execution trail in the event file.
	if len(ev.MatchedRules) == 0 && len(ev.ShadowMatchedRules) == 0 && !ev.Shadow {
		switch ev.SyscallName {
		case "mmap", "openat":
			return
		}
	}
	if format == "json" {
		fields := logrus.Fields{
			"kind":          "security_event",
			"timestamp_ns":  ev.Timestamp,
			"pid":           ev.PID,
			"uid":           ev.UID,
			"username":      ev.Username,
			"process_name":  ev.ProcessName,
			"syscall_name":  ev.SyscallName,
			"cmdline":       ev.Cmdline,
			"arguments":     ev.Arguments,
			"matched_rules": ev.MatchedRules,
			"suppressed_by": ev.SuppressedBy,
		}
		if ev.Shadow || len(ev.ShadowMatchedRules) > 0 {
			fields["shadow"] = ev.Shadow
			fields["shadow_matched_rules"] = ev.ShadowMatchedRules
		}
		if len(ev.MatchedRuleMetadata) > 0 {
			fields["matched_rule_metadata"] = ev.MatchedRuleMetadata
		}
		if len(ev.ShadowRuleMetadata) > 0 {
			fields["shadow_rule_metadata"] = ev.ShadowRuleMetadata
		}
		log.WithFields(fields).Info("event")
		return
	}
	log.Infof(
		"syscall=%s pid=%d uid=%d user=%q comm=%q cmdline=%q matched=%v suppressed_by=%v shadow=%v shadow_matched=%v rule_meta=%+v shadow_meta=%+v args=%v ts_ns=%d",
		ev.SyscallName, ev.PID, ev.UID, ev.Username, ev.ProcessName, ev.Cmdline,
		ev.MatchedRules, ev.SuppressedBy, ev.Shadow, ev.ShadowMatchedRules,
		ev.MatchedRuleMetadata, ev.ShadowRuleMetadata, ev.Arguments, ev.Timestamp,
	)
}
