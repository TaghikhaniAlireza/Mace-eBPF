// Package agentconfig holds YAML configuration for mace-agent.
package agentconfig

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the root YAML document for mace-agent.
type Config struct {
	Logging LoggingConfig `yaml:"logging"`
	Rules   RulesConfig   `yaml:"rules"`
}

// LoggingConfig controls where security events are written (sole sink for events).
type LoggingConfig struct {
	Path   string `yaml:"path"`
	Format string `yaml:"format"` // "json" or "text"
}

// RulesConfig points at the rule YAML file or directory (same semantics as mace.LoadRulesFile).
type RulesConfig struct {
	Path string `yaml:"path"`
}

// Load reads and validates configuration from path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse config yaml: %w", err)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Validate returns an error if required fields are missing or invalid.
func (c *Config) Validate() error {
	if strings.TrimSpace(c.Logging.Path) == "" {
		return fmt.Errorf("logging.path is required")
	}
	f := strings.ToLower(strings.TrimSpace(c.Logging.Format))
	if f != "json" && f != "text" {
		return fmt.Errorf("logging.format must be \"json\" or \"text\", got %q", c.Logging.Format)
	}
	c.Logging.Format = f

	if strings.TrimSpace(c.Rules.Path) == "" {
		return fmt.Errorf("rules.path is required")
	}
	return nil
}
