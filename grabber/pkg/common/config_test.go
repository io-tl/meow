package common

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadConfig_Valid(t *testing.T) {
	yaml := `
nats:
  url: nats://10.0.0.1:4222
  auth:
    token: secret123
fingerprint:
  workers: 20
  probe_timeout_ms: 5000
  global_timeout_ms: 60000
enrichment:
  workers: 10
logging:
  level: debug
  format: json
`
	path := writeTempFile(t, yaml)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.NATS.URL != "nats://10.0.0.1:4222" {
		t.Errorf("NATS.URL = %q", cfg.NATS.URL)
	}
	if cfg.NATS.Auth.Token != "secret123" {
		t.Errorf("NATS.Auth.Token = %q", cfg.NATS.Auth.Token)
	}
	if cfg.Fingerprint.Workers != 20 {
		t.Errorf("Fingerprint.Workers = %d", cfg.Fingerprint.Workers)
	}
	if cfg.Fingerprint.ProbeTimeoutMS != 5000 {
		t.Errorf("ProbeTimeoutMS = %d", cfg.Fingerprint.ProbeTimeoutMS)
	}
	if cfg.Fingerprint.GlobalTimeoutMS != 60000 {
		t.Errorf("GlobalTimeoutMS = %d", cfg.Fingerprint.GlobalTimeoutMS)
	}
	if cfg.Enrichment.Workers != 10 {
		t.Errorf("Enrichment.Workers = %d", cfg.Enrichment.Workers)
	}
	if cfg.Logging.Level != "debug" {
		t.Errorf("Logging.Level = %q", cfg.Logging.Level)
	}
	if cfg.Logging.Format != "json" {
		t.Errorf("Logging.Format = %q", cfg.Logging.Format)
	}
}

func TestLoadConfig_Defaults(t *testing.T) {
	yaml := `
nats:
  auth:
    token: tok
`
	path := writeTempFile(t, yaml)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.NATS.URL != "nats://localhost:4222" {
		t.Errorf("NATS.URL default = %q, want %q", cfg.NATS.URL, "nats://localhost:4222")
	}
	if cfg.Fingerprint.Workers != 500 {
		t.Errorf("Fingerprint.Workers default = %d, want 500", cfg.Fingerprint.Workers)
	}
	if cfg.Fingerprint.ProbeTimeoutMS != 9000 {
		t.Errorf("ProbeTimeoutMS default = %d, want 9000", cfg.Fingerprint.ProbeTimeoutMS)
	}
	if cfg.Fingerprint.GlobalTimeoutMS != 30000 {
		t.Errorf("GlobalTimeoutMS default = %d, want 30000", cfg.Fingerprint.GlobalTimeoutMS)
	}
	if cfg.Enrichment.Workers != 500 {
		t.Errorf("Enrichment.Workers default = %d, want 500", cfg.Enrichment.Workers)
	}
	if cfg.Logging.Level != "info" {
		t.Errorf("Logging.Level default = %q, want %q", cfg.Logging.Level, "info")
	}
	if cfg.Logging.Format != "console" {
		t.Errorf("Logging.Format default = %q, want %q", cfg.Logging.Format, "console")
	}
}

func TestLoadConfig_FileNotFound(t *testing.T) {
	_, err := LoadConfig("/nonexistent/path/config.yaml")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestLoadConfig_InvalidYAML(t *testing.T) {
	path := writeTempFile(t, ":::invalid yaml{{{}}")
	_, err := LoadConfig(path)
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestProbeTimeout(t *testing.T) {
	fc := FingerprintConfig{ProbeTimeoutMS: 3000}
	got := fc.ProbeTimeout()
	want := 3 * time.Second
	if got != want {
		t.Errorf("ProbeTimeout() = %v, want %v", got, want)
	}
}

func TestGlobalTimeout(t *testing.T) {
	fc := FingerprintConfig{GlobalTimeoutMS: 30000}
	got := fc.GlobalTimeout()
	want := 30 * time.Second
	if got != want {
		t.Errorf("GlobalTimeout() = %v, want %v", got, want)
	}
}

func TestTopicConstants(t *testing.T) {
	if TopicPortOpen != "scan.port.open" {
		t.Errorf("TopicPortOpen = %q", TopicPortOpen)
	}
	if TopicPortFingerprinted != "scan.port.fingerprinted" {
		t.Errorf("TopicPortFingerprinted = %q", TopicPortFingerprinted)
	}
	if TopicPortEnriched != "scan.port.enriched" {
		t.Errorf("TopicPortEnriched = %q", TopicPortEnriched)
	}
}

func TestGetTopicMethods(t *testing.T) {
	cfg := &Config{}
	if cfg.GetFingerprintInputTopic() != TopicPortOpen {
		t.Errorf("GetFingerprintInputTopic() = %q", cfg.GetFingerprintInputTopic())
	}
	if cfg.GetFingerprintOutputTopic() != TopicPortFingerprinted {
		t.Errorf("GetFingerprintOutputTopic() = %q", cfg.GetFingerprintOutputTopic())
	}
	if cfg.GetEnrichmentInputTopic() != TopicPortFingerprinted {
		t.Errorf("GetEnrichmentInputTopic() = %q", cfg.GetEnrichmentInputTopic())
	}
	if cfg.GetEnrichmentOutputTopic() != TopicPortEnriched {
		t.Errorf("GetEnrichmentOutputTopic() = %q", cfg.GetEnrichmentOutputTopic())
	}
}

func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	return path
}
