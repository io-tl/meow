package main

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// YAMLConfig represents the simplified structure of the config.yaml file
type YAMLConfig struct {
	NATS    NATSConfig    `yaml:"nats"`
	Synscan SynscanConfig `yaml:"synscan"`
	Logging LoggingConfig `yaml:"logging"`
}

// NATSConfig contains the NATS configuration
type NATSConfig struct {
	URL  string         `yaml:"url"`
	Auth NATSAuthConfig `yaml:"auth"`
}

// NATSAuthConfig contains the NATS authentication
type NATSAuthConfig struct {
	Token string `yaml:"token"`
}

// SynscanConfig contains the scanner configuration
type SynscanConfig struct {
	Target      TargetConfig      `yaml:"target"`
	Network     NetworkConfig     `yaml:"network"`
	Performance PerformanceConfig `yaml:"performance"`
}

// TargetConfig defines the scan targets
type TargetConfig struct {
	CIDR     string `yaml:"cidr"`
	File     string `yaml:"file"`
	Ports    string `yaml:"ports"`
	TopPorts int    `yaml:"top_ports"`
}

// NetworkConfig defines the network parameters
type NetworkConfig struct {
	Interface string `yaml:"interface"`
}

// PerformanceConfig defines the performance parameters
type PerformanceConfig struct {
	RateLimit int `yaml:"rate_limit"`
	TimeoutMS int `yaml:"timeout_ms"`
	// Batch params defined as internal constants (not configurable)
	Batch BatchConfig `yaml:"-"`
}

// BatchConfig contains the batch parameters (internal constants)
type BatchConfig struct {
	Send        int
	Recv        int
	RingSize    int
	IPBatchSize int
}

// LoggingConfig contains the logging configuration
type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

// LoadConfig loads the configuration from a YAML file
func LoadConfig(path string) (*YAMLConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config YAMLConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &config, nil
}

// GetDefaultConfig returns a simplified default configuration
func GetDefaultConfig() *YAMLConfig {
	return &YAMLConfig{
		NATS: NATSConfig{
			URL: "nats://localhost:4222",
			Auth: NATSAuthConfig{
				Token: "",
			},
		},
		Synscan: SynscanConfig{
			Target: TargetConfig{
				CIDR:  "",
				File:  "",
				Ports: "80,443,22,8080,8443",
			},
			Network: NetworkConfig{
				Interface: "",
			},
			Performance: PerformanceConfig{
				RateLimit: 1000,
				TimeoutMS: 5000,
			},
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "console",
		},
	}
}
