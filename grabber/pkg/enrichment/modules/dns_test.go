package modules

import (
	"encoding/json"
	"testing"
)

func TestDNS_ModuleRegistered(t *testing.T) {
	mod, ok := Get("dns")
	if !ok {
		t.Fatal("dns not registered")
	}
	if mod.Name() != "dns" {
		t.Errorf("Name() = %q", mod.Name())
	}
	// Check alias
	_, ok = Get("domain")
	if !ok {
		t.Fatal("domain alias not registered")
	}
}

func TestDNSResult_JSONMarshal(t *testing.T) {
	r := DNSResult{
		Version:      "9.18.0",
		Hostname:     "ns1.example.com",
		SupportsZone: false,
		Recursion:    true,
		DNSSEC:       false,
	}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded DNSResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.Version != "9.18.0" {
		t.Errorf("Version = %q", decoded.Version)
	}
	if !decoded.Recursion {
		t.Error("Recursion = false")
	}
}

func TestDNS_ScanWithSNI_DelegatesToScan(t *testing.T) {
	mod, ok := Get("dns")
	if !ok {
		t.Fatal("dns not registered")
	}
	// DNS doesn't use SNI, ScanWithSNI should delegate to Scan
	// We just verify it doesn't panic (will fail to connect to port 1)
	_, _ = mod.ScanWithSNI("127.0.0.1", 1, "example.com")
}
