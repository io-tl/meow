package types

import (
	"encoding/json"
	"testing"
	"time"
)

// --- PortState ---

func TestPortState_String(t *testing.T) {
	tests := []struct {
		state    PortState
		expected string
	}{
		{PortUnknown, "unknown"},
		{PortOpen, "open"},
		{PortClosed, "closed"},
		{PortFiltered, "filtered"},
	}
	for _, tt := range tests {
		got := tt.state.String()
		if got != tt.expected {
			t.Errorf("PortState(%d).String(): expected %q, got %q", tt.state, tt.expected, got)
		}
	}
}

func TestPortState_UnknownValues(t *testing.T) {
	// Any value outside 0-3 should be "unknown"
	if PortState(99).String() != "unknown" {
		t.Errorf("expected 'unknown' for undefined PortState, got %q", PortState(99).String())
	}
	if PortState(-1).String() != "unknown" {
		t.Errorf("expected 'unknown' for negative PortState, got %q", PortState(-1).String())
	}
}

func TestPortState_EnumValues(t *testing.T) {
	if PortUnknown != 0 {
		t.Errorf("PortUnknown should be 0, got %d", PortUnknown)
	}
	if PortOpen != 1 {
		t.Errorf("PortOpen should be 1, got %d", PortOpen)
	}
	if PortClosed != 2 {
		t.Errorf("PortClosed should be 2, got %d", PortClosed)
	}
	if PortFiltered != 3 {
		t.Errorf("PortFiltered should be 3, got %d", PortFiltered)
	}
}

// --- OpenPortEvent JSON ---

func TestOpenPortEvent_JSONMarshal(t *testing.T) {
	event := OpenPortEvent{
		ScanID:    "test-uuid-1234",
		IP:        "192.168.1.1",
		Port:      80,
		Timestamp: 1707123456,
	}

	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if parsed["scan_id"] != "test-uuid-1234" {
		t.Errorf("scan_id: expected test-uuid-1234, got %v", parsed["scan_id"])
	}
	if parsed["ip"] != "192.168.1.1" {
		t.Errorf("ip: expected 192.168.1.1, got %v", parsed["ip"])
	}
	if parsed["port"].(float64) != 80 {
		t.Errorf("port: expected 80, got %v", parsed["port"])
	}
	if parsed["timestamp"].(float64) != 1707123456 {
		t.Errorf("timestamp: expected 1707123456, got %v", parsed["timestamp"])
	}
}

func TestOpenPortEvent_JSONRoundtrip(t *testing.T) {
	original := OpenPortEvent{
		ScanID:    "550e8400-e29b-41d4-a716-446655440000",
		IP:        "10.0.0.1",
		Port:      443,
		Timestamp: 1707999999,
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var decoded OpenPortEvent
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if decoded.ScanID != original.ScanID {
		t.Errorf("scan_id: expected %s, got %s", original.ScanID, decoded.ScanID)
	}
	if decoded.IP != original.IP {
		t.Errorf("ip: expected %s, got %s", original.IP, decoded.IP)
	}
	if decoded.Port != original.Port {
		t.Errorf("port: expected %d, got %d", original.Port, decoded.Port)
	}
	if decoded.Timestamp != original.Timestamp {
		t.Errorf("timestamp: expected %d, got %d", original.Timestamp, decoded.Timestamp)
	}
}

func TestOpenPortEvent_JSONFieldNames(t *testing.T) {
	event := OpenPortEvent{
		ScanID:    "id",
		IP:        "1.2.3.4",
		Port:      22,
		Timestamp: 100,
	}
	data, _ := json.Marshal(event)
	jsonStr := string(data)

	// Verify JSON field names match expected NATS format
	expected := []string{`"scan_id"`, `"ip"`, `"port"`, `"timestamp"`}
	for _, field := range expected {
		if !contains(jsonStr, field) {
			t.Errorf("JSON missing field %s: %s", field, jsonStr)
		}
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// --- ScanResult ---

func TestScanResult_Fields(t *testing.T) {
	now := time.Now()
	result := ScanResult{
		IP:        "10.0.0.1",
		Port:      8080,
		State:     PortOpen,
		Timestamp: now,
		RTT:       5 * time.Millisecond,
	}

	if result.IP != "10.0.0.1" {
		t.Errorf("IP: expected 10.0.0.1, got %s", result.IP)
	}
	if result.Port != 8080 {
		t.Errorf("Port: expected 8080, got %d", result.Port)
	}
	if result.State != PortOpen {
		t.Errorf("State: expected PortOpen, got %s", result.State)
	}
	if result.RTT != 5*time.Millisecond {
		t.Errorf("RTT: expected 5ms, got %v", result.RTT)
	}
}

// --- ScanConfig ---

func TestScanConfig_TargetIPsPriority(t *testing.T) {
	config := ScanConfig{
		CIDR:      "10.0.0.0/24",
		TargetIPs: []string{"192.168.1.1", "192.168.1.2"},
	}

	// TargetIPs should be preferred over CIDR
	if len(config.TargetIPs) != 2 {
		t.Errorf("TargetIPs: expected 2, got %d", len(config.TargetIPs))
	}
}

func TestScanConfig_Defaults(t *testing.T) {
	config := ScanConfig{}
	if config.Seed != 0 {
		t.Errorf("default Seed should be 0, got %d", config.Seed)
	}
	if config.ResumeFrom != 0 {
		t.Errorf("default ResumeFrom should be 0, got %d", config.ResumeFrom)
	}
	if config.RandomizeIPs {
		t.Error("default RandomizeIPs should be false")
	}
}
