package agentconfig

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_valid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := `logging:
  path: /var/log/mace/events.log
  format: json
rules:
  path: /etc/mace/rules.yaml
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Logging.Path != "/var/log/mace/events.log" || c.Logging.Format != "json" {
		t.Fatalf("logging: %+v", c.Logging)
	}
	if c.Rules.Path != "/etc/mace/rules.yaml" {
		t.Fatalf("rules: %+v", c.Rules)
	}
}

func TestLoad_missingPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(path, []byte("logging:\n  format: json\nrules:\n  path: /x\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for missing logging.path")
	}
}
