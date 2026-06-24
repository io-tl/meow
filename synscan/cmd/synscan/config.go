package main

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// YAMLConfig représente la structure simplifiée du fichier config.yaml
type YAMLConfig struct {
	NATS    NATSConfig    `yaml:"nats"`
	Synscan SynscanConfig `yaml:"synscan"`
	Logging LoggingConfig `yaml:"logging"`
}

// NATSConfig contient la configuration NATS
type NATSConfig struct {
	URL  string         `yaml:"url"`
	Auth NATSAuthConfig `yaml:"auth"`
}

// NATSAuthConfig contient l'authentification NATS
type NATSAuthConfig struct {
	Token string `yaml:"token"`
}

// SynscanConfig contient la configuration du scanner
type SynscanConfig struct {
	Target      TargetConfig      `yaml:"target"`
	Network     NetworkConfig     `yaml:"network"`
	Performance PerformanceConfig `yaml:"performance"`
}

// TargetConfig définit les cibles du scan
type TargetConfig struct {
	CIDR     string `yaml:"cidr"`
	File     string `yaml:"file"`
	Ports    string `yaml:"ports"`
	TopPorts int    `yaml:"top_ports"`
}

// NetworkConfig définit les paramètres réseau
type NetworkConfig struct {
	Interface string `yaml:"interface"`
}

// PerformanceConfig définit les paramètres de performance
type PerformanceConfig struct {
	RateLimit int `yaml:"rate_limit"`
	TimeoutMS int `yaml:"timeout_ms"`
	// Batch params définis en constantes internes (pas configurables)
	Batch BatchConfig `yaml:"-"`
}

// BatchConfig contient les paramètres de batch (constantes internes)
type BatchConfig struct {
	Send        int
	Recv        int
	RingSize    int
	IPBatchSize int
}

// LoggingConfig contient la configuration du logging
type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

// LoadConfig charge la configuration depuis un fichier YAML
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

// GetDefaultConfig retourne une configuration par défaut simplifiée
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
