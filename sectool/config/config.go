package config

import (
	"encoding/json"
	"errors"
	"os"
	"time"
)

const (
	Version           = "0.0.1"
	DefaultBurpMCPURL = "http://127.0.0.1:9876/sse"
)

// Config holds the sectool configuration stored in .sectool/config.json
type Config struct {
	Version       string    `json:"version"`
	InitializedAt time.Time `json:"initialized_at"`
	LastInitMode  string    `json:"last_init_mode,omitempty"`
	BurpMCPURL    string    `json:"burp_mcp_url"`
}

// DefaultConfig returns a new Config with default values
func DefaultConfig(version string) *Config {
	return &Config{
		Version:       version,
		InitializedAt: time.Now().UTC(),
		BurpMCPURL:    DefaultBurpMCPURL,
	}
}

// Load reads and parses config from the given path.
// If the file doesn't exist, returns os.ErrNotExist.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	cfg.applyDefaults()

	return &cfg, nil
}

// Save writes the config to the given path atomically.
func (c *Config) Save(path string) error {
	if c == nil {
		return errors.New("config is nil")
	}

	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}

	// Write atomically by writing to temp file then renaming
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return err
	}

	return os.Rename(tmpPath, path)
}

// applyDefaults fills in zero values with defaults
func (c *Config) applyDefaults() {
	if c.BurpMCPURL == "" {
		c.BurpMCPURL = DefaultBurpMCPURL
	}
}
