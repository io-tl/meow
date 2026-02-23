package modules

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func TestScanPOP3_WithCapabilities(t *testing.T) {
	host, port := startTestTCPServer(t, func(conn net.Conn) {
		reader := bufio.NewReader(conn)
		fmt.Fprintf(conn, "+OK POP3 server ready\r\n")

		// Read CAPA
		reader.ReadString('\n')
		fmt.Fprintf(conn, "+OK Capability list follows\r\n")
		fmt.Fprintf(conn, "USER\r\n")
		fmt.Fprintf(conn, "UIDL\r\n")
		fmt.Fprintf(conn, "STLS\r\n")
		fmt.Fprintf(conn, ".\r\n")

		// Read QUIT
		reader.ReadString('\n')
	})

	result, err := scanPOP3(host, port, false, "", 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Protocol != "pop3" {
		t.Errorf("Protocol = %q, want %q", result.Protocol, "pop3")
	}
	if !strings.Contains(result.Banner, "+OK") {
		t.Errorf("Banner = %q", result.Banner)
	}
	if len(result.Capabilities) == 0 {
		t.Error("Capabilities empty")
	}
}

func TestScanPOP3_ERR(t *testing.T) {
	host, port := startTestTCPServer(t, func(conn net.Conn) {
		fmt.Fprintf(conn, "-ERR Service unavailable\r\n")
	})

	result, err := scanPOP3(host, port, false, "", 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Banner == "" {
		t.Error("Banner empty")
	}
	// POP3 module only sends CAPA if banner starts with +OK
	if len(result.Capabilities) != 0 {
		t.Errorf("Capabilities = %v, want empty for -ERR", result.Capabilities)
	}
}

func TestScanPOP3_Protocol(t *testing.T) {
	host, port := startTestTCPServer(t, func(conn net.Conn) {
		fmt.Fprintf(conn, "+OK Ready\r\n")
		buf := make([]byte, 256)
		conn.Read(buf)
	})

	result, _ := scanPOP3(host, port, false, "", 2*time.Second)
	if result.Protocol != "pop3" {
		t.Errorf("Protocol = %q, want pop3", result.Protocol)
	}
}

func TestPOP3_ModulesRegistered(t *testing.T) {
	_, ok := Get("pop3")
	if !ok {
		t.Fatal("pop3 not registered")
	}
	_, ok = Get("pop3s")
	if !ok {
		t.Fatal("pop3s not registered")
	}
}
