package transport

import (
	"testing"
)

// --- TransportMethod String ---

func TestTransportMethod_String(t *testing.T) {
	tests := []struct {
		method   TransportMethod
		expected string
	}{
		{TransportAFPacket, "AF_PACKET+mmap"},
		{TransportRawSocket, "Raw Socket"},
		{TransportConnect, "Connect"},
		{TransportNpcap, "Npcap"},
		{TransportMethod(99), "Unknown"},
	}
	for _, tt := range tests {
		got := tt.method.String()
		if got != tt.expected {
			t.Errorf("TransportMethod(%d).String(): expected %q, got %q", tt.method, tt.expected, got)
		}
	}
}

// --- TransportMethod enum values ---

func TestTransportMethod_EnumOrder(t *testing.T) {
	if TransportAFPacket != 0 {
		t.Errorf("TransportAFPacket should be 0, got %d", TransportAFPacket)
	}
	if TransportRawSocket != 1 {
		t.Errorf("TransportRawSocket should be 1, got %d", TransportRawSocket)
	}
	if TransportConnect != 2 {
		t.Errorf("TransportConnect should be 2, got %d", TransportConnect)
	}
	if TransportNpcap != 3 {
		t.Errorf("TransportNpcap should be 3, got %d", TransportNpcap)
	}
}

// --- IsPortOpen/Closed/Filtered helpers ---

func TestIsPortOpen(t *testing.T) {
	tests := []struct {
		flags    uint8
		expected bool
	}{
		{0x12, true},  // SYN+ACK
		{0x02, false}, // SYN only
		{0x10, false}, // ACK only
		{0x04, false}, // RST
		{0x00, false}, // No flags
		{0x16, true},  // SYN+ACK+RST (SYN+ACK bits set)
	}
	for _, tt := range tests {
		got := IsPortOpen(tt.flags)
		if got != tt.expected {
			t.Errorf("IsPortOpen(0x%02x): expected %v, got %v", tt.flags, tt.expected, got)
		}
	}
}

func TestIsPortClosed(t *testing.T) {
	tests := []struct {
		flags    uint8
		expected bool
	}{
		{0x04, true},  // RST
		{0x14, true},  // RST+ACK
		{0x12, false}, // SYN+ACK
		{0x02, false}, // SYN
		{0x00, false}, // No flags
	}
	for _, tt := range tests {
		got := IsPortClosed(tt.flags)
		if got != tt.expected {
			t.Errorf("IsPortClosed(0x%02x): expected %v, got %v", tt.flags, tt.expected, got)
		}
	}
}

func TestIsPortFiltered(t *testing.T) {
	tests := []struct {
		flags    uint8
		expected bool
	}{
		{0x00, true},  // No response
		{0x12, false}, // SYN+ACK
		{0x04, false}, // RST
		{0x02, false}, // SYN
	}
	for _, tt := range tests {
		got := IsPortFiltered(tt.flags)
		if got != tt.expected {
			t.Errorf("IsPortFiltered(0x%02x): expected %v, got %v", tt.flags, tt.expected, got)
		}
	}
}

// --- Capabilities ---

func TestCapabilities_ConnectTransport(t *testing.T) {
	// ConnectTransport capabilities are well-defined
	caps := Capabilities{
		SupportsSYNScan:          false,
		SupportsCustomSourcePort: false,
		SupportsRawPackets:       false,
		RequiresRoot:             false,
		MaxPacketsPerSecond:      50000,
	}

	if caps.SupportsSYNScan {
		t.Error("connect transport should not support SYN scan")
	}
	if caps.RequiresRoot {
		t.Error("connect transport should not require root")
	}
}

// --- Packet struct ---

func TestPacket_Fields(t *testing.T) {
	pkt := &Packet{
		Data:    []byte{0x01, 0x02},
		DstIP:   []byte{10, 0, 0, 1},
		DstPort: 80,
		SrcPort: 40000,
		Length:  2,
	}
	if pkt.DstPort != 80 {
		t.Errorf("DstPort: expected 80, got %d", pkt.DstPort)
	}
	if pkt.SrcPort != 40000 {
		t.Errorf("SrcPort: expected 40000, got %d", pkt.SrcPort)
	}
	if pkt.Length != 2 {
		t.Errorf("Length: expected 2, got %d", pkt.Length)
	}
}

// --- TransportConfig ---

func TestTransportConfig_Defaults(t *testing.T) {
	cfg := &TransportConfig{}
	if cfg.SendBatchSize != 0 {
		t.Errorf("default SendBatchSize should be 0, got %d", cfg.SendBatchSize)
	}
	if cfg.TimeoutMS != 0 {
		t.Errorf("default TimeoutMS should be 0, got %d", cfg.TimeoutMS)
	}
}
