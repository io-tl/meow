package types

import (
	"errors"
	"testing"
	"time"
)

func TestNewEnrichmentResult_Fields(t *testing.T) {
	r := NewEnrichmentResult("1.2.3.4", 80, "http", "example.com", "test-data")
	if r.IP != "1.2.3.4" {
		t.Errorf("IP = %q, want %q", r.IP, "1.2.3.4")
	}
	if r.Port != 80 {
		t.Errorf("Port = %d, want 80", r.Port)
	}
	if r.Service != "http" {
		t.Errorf("Service = %q, want %q", r.Service, "http")
	}
	if r.Domain != "example.com" {
		t.Errorf("Domain = %q, want %q", r.Domain, "example.com")
	}
	if r.Data != "test-data" {
		t.Errorf("Data = %v, want %q", r.Data, "test-data")
	}
	if r.Error != "" {
		t.Errorf("Error = %q, want empty", r.Error)
	}
}

func TestNewEnrichmentResult_Timestamp(t *testing.T) {
	before := time.Now().UTC().Truncate(time.Second)
	r := NewEnrichmentResult("1.2.3.4", 80, "http", "", nil)
	after := time.Now().UTC().Truncate(time.Second).Add(time.Second)

	ts, err := time.Parse(time.RFC3339, r.Timestamp)
	if err != nil {
		t.Fatalf("timestamp not valid RFC3339: %v", err)
	}
	if ts.Before(before) || ts.After(after) {
		t.Errorf("timestamp %v not between %v and %v", ts, before, after)
	}
}

func TestNewEnrichmentResult_NoDomain(t *testing.T) {
	r := NewEnrichmentResult("1.2.3.4", 22, "ssh", "", nil)
	if r.Domain != "" {
		t.Errorf("Domain = %q, want empty", r.Domain)
	}
}

func TestNewEnrichmentError_Fields(t *testing.T) {
	err := errors.New("connection refused")
	r := NewEnrichmentError("1.2.3.4", 3306, "mysql", "", err)
	if r.IP != "1.2.3.4" {
		t.Errorf("IP = %q", r.IP)
	}
	if r.Port != 3306 {
		t.Errorf("Port = %d", r.Port)
	}
	if r.Service != "mysql" {
		t.Errorf("Service = %q", r.Service)
	}
	if r.Error != "connection refused" {
		t.Errorf("Error = %q, want %q", r.Error, "connection refused")
	}
	if r.Data != nil {
		t.Errorf("Data = %v, want nil", r.Data)
	}
}

func TestNewEnrichmentError_Timestamp(t *testing.T) {
	r := NewEnrichmentError("1.2.3.4", 80, "http", "", errors.New("fail"))
	_, err := time.Parse(time.RFC3339, r.Timestamp)
	if err != nil {
		t.Fatalf("timestamp not valid RFC3339: %v", err)
	}
}

func TestNewEnrichmentResult_WithDomain(t *testing.T) {
	r := NewEnrichmentResult("1.2.3.4", 443, "https", "example.com", nil)
	if r.Domain != "example.com" {
		t.Errorf("Domain = %q, want %q", r.Domain, "example.com")
	}
}

func TestNewEnrichmentError_WithDomain(t *testing.T) {
	r := NewEnrichmentError("1.2.3.4", 443, "https", "example.com", errors.New("tls error"))
	if r.Domain != "example.com" {
		t.Errorf("Domain = %q, want %q", r.Domain, "example.com")
	}
}
