package modules

import (
	"bufio"
	"fmt"
	"net"
	"testing"
	"time"
)

func TestScanSMTP_FullServer(t *testing.T) {
	host, port := startTestTCPServer(t, func(conn net.Conn) {
		reader := bufio.NewReader(conn)
		// Send banner
		fmt.Fprintf(conn, "220 mail.example.com ESMTP Postfix\r\n")

		// Read EHLO
		reader.ReadString('\n')

		// Send EHLO response
		fmt.Fprintf(conn, "250-mail.example.com Hello\r\n")
		fmt.Fprintf(conn, "250-SIZE 52428800\r\n")
		fmt.Fprintf(conn, "250-STARTTLS\r\n")
		fmt.Fprintf(conn, "250-AUTH PLAIN LOGIN\r\n")
		fmt.Fprintf(conn, "250 8BITMIME\r\n")

		// Read QUIT
		reader.ReadString('\n')
	})

	result, err := scanSMTP(host, port, 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Banner == "" {
		t.Error("Banner empty")
	}
	if result.Hostname != "mail.example.com" {
		t.Errorf("Hostname = %q, want %q", result.Hostname, "mail.example.com")
	}
	if !result.SupportsTLS {
		t.Error("SupportsTLS = false")
	}
	if !result.SupportsAuth {
		t.Error("SupportsAuth = false")
	}
	if len(result.AuthMethods) != 2 {
		t.Errorf("AuthMethods = %v, want [PLAIN LOGIN]", result.AuthMethods)
	}
	if len(result.Commands) == 0 {
		t.Error("Commands empty")
	}
}

func TestScanSMTP_BannerOnly(t *testing.T) {
	host, port := startTestTCPServer(t, func(conn net.Conn) {
		fmt.Fprintf(conn, "220 mail.example.com ESMTP\r\n")
		// Read EHLO then close
		buf := make([]byte, 256)
		conn.Read(buf)
	})

	result, err := scanSMTP(host, port, 2*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Banner == "" {
		t.Error("Banner empty")
	}
	if result.SupportsTLS {
		t.Error("SupportsTLS should be false without EHLO response")
	}
}

func TestSMTP_ModuleRegistered(t *testing.T) {
	mod, ok := Get("smtp")
	if !ok {
		t.Fatal("smtp module not registered")
	}
	// Check aliases
	_, ok = Get("smtps")
	if !ok {
		t.Error("smtps alias not registered")
	}
	_, ok = Get("submission")
	if !ok {
		t.Error("submission alias not registered")
	}
	if !mod.ShouldEnrich() {
		t.Error("ShouldEnrich() = false")
	}
}
