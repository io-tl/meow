package modules

import (
	"net"
	"testing"
	"time"
)

func TestScanTelnet_IACAndBanner(t *testing.T) {
	host, port := startTestTCPServer(t, func(conn net.Conn) {
		// Send IAC DO Echo (255, 253, 1)
		conn.Write([]byte{255, 253, 1})
		// Send IAC WILL Suppress Go Ahead (255, 251, 3)
		conn.Write([]byte{255, 251, 3})
		// Send text banner
		conn.Write([]byte("Login: "))
		// Read negotiation responses, then close
		buf := make([]byte, 256)
		conn.Read(buf)
	})

	result, err := scanTelnet(host, port, 3*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Protocol != "telnet" {
		t.Errorf("Protocol = %q", result.Protocol)
	}
	if len(result.Options) < 2 {
		t.Errorf("expected at least 2 options, got %d: %v", len(result.Options), result.Options)
	}
	if result.Banner != "Login: " {
		t.Errorf("Banner = %q, want %q", result.Banner, "Login: ")
	}
}

func TestScanTelnet_PlainText(t *testing.T) {
	host, port := startTestTCPServer(t, func(conn net.Conn) {
		conn.Write([]byte("Welcome to the system\r\n"))
	})

	result, err := scanTelnet(host, port, 3*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Banner == "" {
		t.Error("Banner empty for plain text server")
	}
	if len(result.Options) != 0 {
		t.Errorf("Options = %v, want empty", result.Options)
	}
}

func TestScanTelnet_ServerClosesImmediately(t *testing.T) {
	host, port := startTestTCPServer(t, func(conn net.Conn) {
		// Close immediately
	})

	result, err := scanTelnet(host, port, 2*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should not panic
	if result.Protocol != "telnet" {
		t.Errorf("Protocol = %q", result.Protocol)
	}
}

func TestTelnet_ModuleRegistered(t *testing.T) {
	_, ok := Get("telnet")
	if !ok {
		t.Fatal("telnet module not registered")
	}
}
