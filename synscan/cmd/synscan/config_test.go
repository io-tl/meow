package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGetDefaultConfig(t *testing.T) {
	config := GetDefaultConfig()

	if config.NATS.URL != "nats://localhost:4222" {
		t.Errorf("default NATS URL: expected nats://localhost:4222, got %s", config.NATS.URL)
	}
	if config.NATS.Auth.Token != "" {
		t.Errorf("default NATS token should be empty, got %s", config.NATS.Auth.Token)
	}
	if config.Synscan.Target.Ports != "80,443,22,8080,8443" {
		t.Errorf("default ports: expected 80,443,22,8080,8443, got %s", config.Synscan.Target.Ports)
	}
	if config.Synscan.Target.CIDR != "" {
		t.Errorf("default CIDR should be empty, got %s", config.Synscan.Target.CIDR)
	}
	if config.Synscan.Target.File != "" {
		t.Errorf("default target file should be empty, got %s", config.Synscan.Target.File)
	}
	if config.Synscan.Network.Interface != "" {
		t.Errorf("default interface should be empty, got %s", config.Synscan.Network.Interface)
	}
	if config.Synscan.Performance.RateLimit != 1000 {
		t.Errorf("default rate limit: expected 1000, got %d", config.Synscan.Performance.RateLimit)
	}
	if config.Synscan.Performance.TimeoutMS != 5000 {
		t.Errorf("default timeout: expected 5000, got %d", config.Synscan.Performance.TimeoutMS)
	}
	if config.Logging.Level != "info" {
		t.Errorf("default log level: expected info, got %s", config.Logging.Level)
	}
	if config.Logging.Format != "console" {
		t.Errorf("default log format: expected console, got %s", config.Logging.Format)
	}
}

func TestLoadConfig_ValidYAML(t *testing.T) {
	yaml := `
nats:
  url: "nats://10.0.0.1:4222"
  auth:
    token: "mytoken"
synscan:
  target:
    cidr: "10.0.0.0/24"
    file: "targets.txt"
    ports: "22,80"
  network:
    interface: "eth0"
  performance:
    rate_limit: 5000
    timeout_ms: 3000
logging:
  level: "debug"
  format: "json"
`
	path := writeTempFile(t, "config-*.yaml", yaml)

	config, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if config.NATS.URL != "nats://10.0.0.1:4222" {
		t.Errorf("NATS URL: expected nats://10.0.0.1:4222, got %s", config.NATS.URL)
	}
	if config.NATS.Auth.Token != "mytoken" {
		t.Errorf("NATS token: expected mytoken, got %s", config.NATS.Auth.Token)
	}
	if config.Synscan.Target.CIDR != "10.0.0.0/24" {
		t.Errorf("CIDR: expected 10.0.0.0/24, got %s", config.Synscan.Target.CIDR)
	}
	if config.Synscan.Target.File != "targets.txt" {
		t.Errorf("file: expected targets.txt, got %s", config.Synscan.Target.File)
	}
	if config.Synscan.Target.Ports != "22,80" {
		t.Errorf("ports: expected 22,80, got %s", config.Synscan.Target.Ports)
	}
	if config.Synscan.Network.Interface != "eth0" {
		t.Errorf("interface: expected eth0, got %s", config.Synscan.Network.Interface)
	}
	if config.Synscan.Performance.RateLimit != 5000 {
		t.Errorf("rate limit: expected 5000, got %d", config.Synscan.Performance.RateLimit)
	}
	if config.Synscan.Performance.TimeoutMS != 3000 {
		t.Errorf("timeout: expected 3000, got %d", config.Synscan.Performance.TimeoutMS)
	}
	if config.Logging.Level != "debug" {
		t.Errorf("log level: expected debug, got %s", config.Logging.Level)
	}
}

func TestLoadConfig_PartialYAML(t *testing.T) {
	// Only NATS section - other fields should be zero values
	yaml := `
nats:
  url: "nats://custom:4222"
`
	path := writeTempFile(t, "config-partial-*.yaml", yaml)

	config, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if config.NATS.URL != "nats://custom:4222" {
		t.Errorf("NATS URL: expected nats://custom:4222, got %s", config.NATS.URL)
	}
	// Unset fields should be Go zero values
	if config.Synscan.Target.CIDR != "" {
		t.Errorf("CIDR should be empty, got %s", config.Synscan.Target.CIDR)
	}
	if config.Synscan.Performance.RateLimit != 0 {
		t.Errorf("rate limit should be 0 (zero value), got %d", config.Synscan.Performance.RateLimit)
	}
}

func TestLoadConfig_EmptyFile(t *testing.T) {
	path := writeTempFile(t, "config-empty-*.yaml", "")

	config, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should parse as empty config with zero values
	if config.NATS.URL != "" {
		t.Errorf("NATS URL should be empty, got %s", config.NATS.URL)
	}
}

func TestLoadConfig_InvalidYAML(t *testing.T) {
	yaml := `
nats:
  url: [invalid
  broken yaml {{{
`
	path := writeTempFile(t, "config-invalid-*.yaml", yaml)

	_, err := LoadConfig(path)
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestLoadConfig_FileNotFound(t *testing.T) {
	_, err := LoadConfig("/tmp/nonexistent-config-xyz-123456.yaml")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestLoadConfig_BatchParamsNotConfigurable(t *testing.T) {
	// Batch params have yaml:"-" tag, so they should be ignored from YAML
	yaml := `
synscan:
  performance:
    rate_limit: 2000
`
	path := writeTempFile(t, "config-batch-*.yaml", yaml)

	config, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Batch params should remain zero (not configurable via YAML)
	if config.Synscan.Performance.Batch.Send != 0 {
		t.Errorf("batch send should be 0 (not configurable), got %d", config.Synscan.Performance.Batch.Send)
	}
	if config.Synscan.Performance.Batch.Recv != 0 {
		t.Errorf("batch recv should be 0 (not configurable), got %d", config.Synscan.Performance.Batch.Recv)
	}
}

// --- loadConfiguration ---

func TestLoadConfiguration_DefaultsWhenNoFile(t *testing.T) {
	opts := cliOptions{
		configFile: "/tmp/nonexistent-config-xyz.yaml",
		target:     "10.0.0.0/24",
	}
	config := loadConfiguration(opts)

	// Should fall back to defaults
	if config.NATS.URL != "nats://localhost:4222" {
		t.Errorf("expected default NATS URL, got %s", config.NATS.URL)
	}
	if config.Synscan.Target.CIDR != "10.0.0.0/24" {
		t.Errorf("CLI target override failed, got %s", config.Synscan.Target.CIDR)
	}
}

func TestLoadConfiguration_CLIOverridesYAML(t *testing.T) {
	yaml := `
nats:
  url: "nats://yaml:4222"
  auth:
    token: "yaml-token"
synscan:
  target:
    cidr: "10.0.0.0/24"
    file: "targets.txt"
    ports: "80"
  performance:
    rate_limit: 500
    timeout_ms: 2000
`
	path := writeTempFile(t, "config-override-*.yaml", yaml)

	opts := cliOptions{
		configFile: path,
		target:     "192.168.1.0/24",
		ports:      "443,8080",
		rateLimit:  9000,
		timeout:    7000,
		natsURL:    "nats://cli:4222",
		natsToken:  "cli-token",
		iface:      "eth1",
	}
	config := loadConfiguration(opts)

	if config.Synscan.Target.CIDR != "192.168.1.0/24" {
		t.Errorf("expected CLI target, got %s", config.Synscan.Target.CIDR)
	}
	if config.Synscan.Target.File != "" {
		t.Errorf("expected CLI target to clear YAML target file, got %s", config.Synscan.Target.File)
	}
	if config.Synscan.Target.Ports != "443,8080" {
		t.Errorf("expected CLI ports, got %s", config.Synscan.Target.Ports)
	}
	if config.Synscan.Performance.RateLimit != 9000 {
		t.Errorf("expected CLI rate limit 9000, got %d", config.Synscan.Performance.RateLimit)
	}
	if config.Synscan.Performance.TimeoutMS != 7000 {
		t.Errorf("expected CLI timeout 7000, got %d", config.Synscan.Performance.TimeoutMS)
	}
	if config.NATS.URL != "nats://cli:4222" {
		t.Errorf("expected CLI NATS URL, got %s", config.NATS.URL)
	}
	if config.NATS.Auth.Token != "cli-token" {
		t.Errorf("expected CLI NATS token, got %s", config.NATS.Auth.Token)
	}
	if config.Synscan.Network.Interface != "eth1" {
		t.Errorf("expected CLI interface, got %s", config.Synscan.Network.Interface)
	}
}

func TestLoadConfiguration_YAMLValuesUsedWhenNoCLI(t *testing.T) {
	yaml := `
nats:
  url: "nats://yaml:4222"
synscan:
  target:
    cidr: "172.16.0.0/16"
    ports: "22,80,443"
  performance:
    rate_limit: 3000
    timeout_ms: 8000
`
	path := writeTempFile(t, "config-yaml-values-*.yaml", yaml)

	opts := cliOptions{
		configFile: path,
	}
	config := loadConfiguration(opts)

	if config.Synscan.Target.CIDR != "172.16.0.0/16" {
		t.Errorf("expected YAML CIDR, got %s", config.Synscan.Target.CIDR)
	}
	if config.Synscan.Target.Ports != "22,80,443" {
		t.Errorf("expected YAML ports, got %s", config.Synscan.Target.Ports)
	}
	if config.Synscan.Performance.RateLimit != 3000 {
		t.Errorf("expected YAML rate limit, got %d", config.Synscan.Performance.RateLimit)
	}
}

func TestLoadConfiguration_CLITargetFileOverridesYAMLTarget(t *testing.T) {
	yaml := `
synscan:
  target:
    cidr: "172.16.0.0/16"
    ports: "22,80,443"
`
	path := writeTempFile(t, "config-target-file-*.yaml", yaml)

	opts := cliOptions{
		configFile: path,
		targetFile: "scopes.txt",
	}
	config := loadConfiguration(opts)

	if config.Synscan.Target.File != "scopes.txt" {
		t.Errorf("expected CLI target file, got %s", config.Synscan.Target.File)
	}
	if config.Synscan.Target.CIDR != "" {
		t.Errorf("expected CLI target file to clear YAML CIDR, got %s", config.Synscan.Target.CIDR)
	}
}

func TestLoadConfiguration_BatchConstantsAlwaysSet(t *testing.T) {
	opts := cliOptions{
		configFile: "/tmp/nonexistent.yaml",
		target:     "10.0.0.0/24",
	}
	config := loadConfiguration(opts)

	if config.Synscan.Performance.Batch.Send != 64 {
		t.Errorf("batch send: expected 64, got %d", config.Synscan.Performance.Batch.Send)
	}
	if config.Synscan.Performance.Batch.Recv != 64 {
		t.Errorf("batch recv: expected 64, got %d", config.Synscan.Performance.Batch.Recv)
	}
	if config.Synscan.Performance.Batch.RingSize != 4096 {
		t.Errorf("ring size: expected 4096, got %d", config.Synscan.Performance.Batch.RingSize)
	}
	if config.Synscan.Performance.Batch.IPBatchSize != 4096 {
		t.Errorf("IP batch size: expected 4096, got %d", config.Synscan.Performance.Batch.IPBatchSize)
	}
}

func TestLoadConfiguration_DefaultsForZeroValues(t *testing.T) {
	// YAML with zero rate limit and timeout
	yaml := `
synscan:
  performance:
    rate_limit: 0
    timeout_ms: 0
`
	path := writeTempFile(t, "config-zero-*.yaml", yaml)

	opts := cliOptions{
		configFile: path,
	}
	config := loadConfiguration(opts)

	// Zero values should be replaced with defaults
	if config.Synscan.Performance.RateLimit != 1000 {
		t.Errorf("zero rate limit should become 1000, got %d", config.Synscan.Performance.RateLimit)
	}
	if config.Synscan.Performance.TimeoutMS != 5000 {
		t.Errorf("zero timeout should become 5000, got %d", config.Synscan.Performance.TimeoutMS)
	}
}

// --- helper ---

func writeTempFile(t *testing.T, pattern, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, pattern)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	return path
}
