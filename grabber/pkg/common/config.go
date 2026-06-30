package common

import (
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the simplified configuration
type Config struct {
	NATS        NATSConfig        `yaml:"nats"`
	Fingerprint FingerprintConfig `yaml:"fingerprint"`
	Enrichment  EnrichmentConfig  `yaml:"enrichment"`
	Logging     LoggingConfig     `yaml:"logging"`
}

// NATSConfig contains the NATS configuration
type NATSConfig struct {
	URL  string     `yaml:"url"`
	Auth AuthConfig `yaml:"auth"`
}

// AuthConfig contains the NATS authentication
type AuthConfig struct {
	Token string `yaml:"token"`
}

// FingerprintConfig contains the configuration for fingerprinting
type FingerprintConfig struct {
	Workers         int `yaml:"workers"`
	ProbeTimeoutMS  int `yaml:"probe_timeout_ms"`
	GlobalTimeoutMS int `yaml:"global_timeout_ms"`
}

// EnrichmentConfig contains the configuration for enrichment
type EnrichmentConfig struct {
	Workers         int `yaml:"workers"`
	EnrichTimeoutMS int `yaml:"enrich_timeout_ms"`
	GlobalTimeoutMS int `yaml:"global_timeout_ms"`
}

// LoggingConfig contains the logging configuration
type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

// ProbeTimeout returns the per-probe timeout
func (c *FingerprintConfig) ProbeTimeout() time.Duration {
	return time.Duration(c.ProbeTimeoutMS) * time.Millisecond
}

// GlobalTimeout returns the global timeout
func (c *FingerprintConfig) GlobalTimeout() time.Duration {
	return time.Duration(c.GlobalTimeoutMS) * time.Millisecond
}

// EnrichTimeout returns the per-enrichment-module timeout (0 = use the module's default)
func (c *EnrichmentConfig) EnrichTimeout() time.Duration {
	return time.Duration(c.EnrichTimeoutMS) * time.Millisecond
}

// GlobalTimeout returns the global timeout for an enrichment job (0 = no limit)
func (c *EnrichmentConfig) GlobalTimeout() time.Duration {
	return time.Duration(c.GlobalTimeoutMS) * time.Millisecond
}

// NATS topics constants (hardcoded - not user-configurable)
const (
	TopicPortOpen          = "scan.port.open"
	TopicPortFingerprinted = "scan.port.fingerprinted"
	TopicPortEnriched      = "scan.port.enriched"
	TopicEnrichRequest     = "scan.enrichment.request"
)

// applyDefaults sets default values on a Config
func applyDefaults(cfg *Config) {
	if cfg.NATS.URL == "" {
		cfg.NATS.URL = "nats://localhost:4222"
	}
	if cfg.Fingerprint.Workers == 0 {
		cfg.Fingerprint.Workers = 500
	}
	if cfg.Fingerprint.ProbeTimeoutMS == 0 {
		cfg.Fingerprint.ProbeTimeoutMS = 9000
	}
	if cfg.Fingerprint.GlobalTimeoutMS == 0 {
		cfg.Fingerprint.GlobalTimeoutMS = 30000
	}
	if cfg.Enrichment.Workers == 0 {
		cfg.Enrichment.Workers = 500
	}
	if cfg.Enrichment.EnrichTimeoutMS == 0 {
		cfg.Enrichment.EnrichTimeoutMS = 10000
	}
	if cfg.Enrichment.GlobalTimeoutMS == 0 {
		cfg.Enrichment.GlobalTimeoutMS = 30000
	}
	if cfg.Logging.Level == "" {
		cfg.Logging.Level = "info"
	}
	if cfg.Logging.Format == "" {
		cfg.Logging.Format = "console"
	}
}

// DefaultConfig returns a Config with all default values
func DefaultConfig() *Config {
	cfg := &Config{}
	applyDefaults(cfg)
	return cfg
}

// LoadConfig loads the configuration from a YAML file
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	applyDefaults(&cfg)

	return &cfg, nil
}

// GetFingerprintInputTopic returns the fingerprint input topic (constant)
func (c *Config) GetFingerprintInputTopic() string {
	return TopicPortOpen
}

// GetFingerprintOutputTopic returns the fingerprint output topic (constant)
func (c *Config) GetFingerprintOutputTopic() string {
	return TopicPortFingerprinted
}

// GetEnrichmentInputTopic returns the enrichment input topic (constant)
func (c *Config) GetEnrichmentInputTopic() string {
	return TopicPortFingerprinted
}

// GetEnrichmentOutputTopic returns the enrichment output topic (constant)
func (c *Config) GetEnrichmentOutputTopic() string {
	return TopicPortEnriched
}

// GetEnrichmentRequestTopic returns the dedicated enrichment request topic (constant)
func (c *Config) GetEnrichmentRequestTopic() string {
	return TopicEnrichRequest
}
