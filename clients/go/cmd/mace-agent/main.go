// Command mace-agent is the standalone Mace eBPF security agent (systemd-friendly).
package main

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
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
	cmd := &cobra.Command{
		Use:          "mace-agent",
		Short:        "Mace eBPF security agent",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(configPath)
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", "", "path to configuration file (required)")
	_ = cmd.MarkFlagRequired("config")
	return cmd
}

func run(configPath string) error {
	cfg, err := agentconfig.Load(configPath)
	if err != nil {
		return err
	}

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
	if format == "json" {
		log.WithFields(logrus.Fields{
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
		}).Info("event")
		return
	}
	log.Infof(
		"syscall=%s pid=%d uid=%d user=%q comm=%q cmdline=%q matched=%v suppressed_by=%v args=%v ts_ns=%d",
		ev.SyscallName, ev.PID, ev.UID, ev.Username, ev.ProcessName, ev.Cmdline,
		ev.MatchedRules, ev.SuppressedBy, ev.Arguments, ev.Timestamp,
	)
}
