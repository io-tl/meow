package modules

import (
	"net"
	"testing"
	"time"
)

func buildMySQLHandshake(version string) []byte {
	// Build a valid MySQL handshake packet
	var packet []byte
	// Protocol version 10
	packet = append(packet, 10)
	// Server version (null-terminated)
	packet = append(packet, []byte(version)...)
	packet = append(packet, 0x00)
	// Connection ID (4 bytes)
	packet = append(packet, 0x01, 0x00, 0x00, 0x00)
	// Auth plugin data part 1 (8 bytes)
	packet = append(packet, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08)
	// Filler (1 byte)
	packet = append(packet, 0x00)
	// Capability flags lower (2 bytes)
	packet = append(packet, 0xFF, 0xF7)
	// Character set (1 byte)
	packet = append(packet, 0x21)
	// Status flags (2 bytes)
	packet = append(packet, 0x02, 0x00)
	// Capability flags upper (2 bytes)
	packet = append(packet, 0x7F, 0x80)
	// Reserved (10 bytes)
	packet = append(packet, make([]byte, 10)...)
	// Auth plugin data part 2 (13 bytes)
	packet = append(packet, make([]byte, 13)...)
	// Auth plugin name (null-terminated)
	plugin := "mysql_native_password"
	packet = append(packet, []byte(plugin)...)
	packet = append(packet, 0x00)

	// Build header: 3 bytes length + 1 byte sequence number
	packetLen := len(packet)
	header := []byte{
		byte(packetLen),
		byte(packetLen >> 8),
		byte(packetLen >> 16),
		0, // sequence number
	}
	return append(header, packet...)
}

func TestScanMySQL_ValidHandshake(t *testing.T) {
	host, port := startTestTCPServer(t, func(conn net.Conn) {
		conn.Write(buildMySQLHandshake("8.0.32"))
	})

	result, err := scanMySQL(host, port, 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Protocol != "mysql" {
		t.Errorf("Protocol = %q", result.Protocol)
	}
	if result.Version != "8.0.32" {
		t.Errorf("Version = %q", result.Version)
	}
	if result.AuthPlugin != "mysql_native_password" {
		t.Errorf("AuthPlugin = %q, want %q", result.AuthPlugin, "mysql_native_password")
	}
	if result.Capabilities == 0 {
		t.Error("Capabilities = 0, want non-zero")
	}
}

func TestScanMySQL_TruncatedHandshake(t *testing.T) {
	host, port := startTestTCPServer(t, func(conn net.Conn) {
		// Send header indicating large packet but only send partial data
		header := []byte{0x05, 0x00, 0x00, 0x00} // 5 bytes packet
		packet := []byte{10, 'x', 0x00, 0x01, 0x02}
		conn.Write(append(header, packet...))
	})

	result, err := scanMySQL(host, port, 3*time.Second)
	// Should not panic
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Protocol != "mysql" {
		t.Errorf("Protocol = %q", result.Protocol)
	}
}

func TestScanMySQL_EmptyPacket(t *testing.T) {
	host, port := startTestTCPServer(t, func(conn net.Conn) {
		// Close immediately
	})

	result, err := scanMySQL(host, port, 2*time.Second)
	if err == nil {
		// Error is expected when we can't read the header
		if result.Error == "" {
			t.Error("expected Error to be set")
		}
	}
}

func TestMySQL_ModuleRegistered(t *testing.T) {
	_, ok := Get("mysql")
	if !ok {
		t.Fatal("mysql module not registered")
	}
}
