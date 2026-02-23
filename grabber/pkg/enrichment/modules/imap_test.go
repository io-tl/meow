package modules

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func TestScanIMAP_PlainWithCapabilities(t *testing.T) {
	host, port := startTestTCPServer(t, func(conn net.Conn) {
		reader := bufio.NewReader(conn)
		// Send banner
		fmt.Fprintf(conn, "* OK IMAP4rev1 Server Ready\r\n")

		// Read CAPABILITY command
		line, _ := reader.ReadString('\n')
		if strings.Contains(line, "CAPABILITY") {
			fmt.Fprintf(conn, "* CAPABILITY IMAP4rev1 IDLE NAMESPACE\r\n")
			fmt.Fprintf(conn, "A001 OK CAPABILITY completed\r\n")
		}

		// Read LOGOUT
		reader.ReadString('\n')
		fmt.Fprintf(conn, "* BYE Server logging out\r\n")
		fmt.Fprintf(conn, "A002 OK LOGOUT completed\r\n")
	})

	result, err := scanIMAP(host, port, false, "", 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Protocol != "imap" {
		t.Errorf("Protocol = %q, want %q", result.Protocol, "imap")
	}
	if !strings.Contains(result.Banner, "OK") {
		t.Errorf("Banner = %q", result.Banner)
	}
	if len(result.Capabilities) == 0 {
		t.Error("expected non-empty Capabilities")
	}
	found := false
	for _, cap := range result.Capabilities {
		if cap == "IMAP4rev1" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Capabilities = %v, want IMAP4rev1", result.Capabilities)
	}
}

func TestScanIMAP_CapabilityNotSupported(t *testing.T) {
	host, port := startTestTCPServer(t, func(conn net.Conn) {
		reader := bufio.NewReader(conn)
		fmt.Fprintf(conn, "* OK IMAP ready\r\n")

		// Read CAPABILITY
		reader.ReadString('\n')
		fmt.Fprintf(conn, "A001 NO CAPABILITY not supported\r\n")

		// Read LOGOUT
		reader.ReadString('\n')
	})

	result, err := scanIMAP(host, port, false, "", 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Banner == "" {
		t.Error("Banner empty")
	}
	if len(result.Capabilities) != 0 {
		t.Errorf("Capabilities = %v, want empty", result.Capabilities)
	}
}

func TestScanIMAP_WriterSendsCommands(t *testing.T) {
	var receivedLines []string
	done := make(chan struct{})
	host, port := startTestTCPServer(t, func(conn net.Conn) {
		defer close(done)
		reader := bufio.NewReader(conn)
		fmt.Fprintf(conn, "* OK IMAP ready\r\n")

		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				break
			}
			receivedLines = append(receivedLines, strings.TrimSpace(line))
			if strings.Contains(line, "CAPABILITY") {
				fmt.Fprintf(conn, "A001 OK done\r\n")
			}
			if strings.Contains(line, "LOGOUT") {
				fmt.Fprintf(conn, "A002 OK bye\r\n")
				break
			}
		}
	})

	scanIMAP(host, port, false, "", 5*time.Second)

	// Wait for server goroutine to finish reading
	select {
	case <-done:
	case <-time.After(3 * time.Second):
	}

	// Verify CAPABILITY was sent
	capFound := false
	logoutFound := false
	for _, line := range receivedLines {
		if strings.Contains(line, "CAPABILITY") {
			capFound = true
		}
		if strings.Contains(line, "LOGOUT") {
			logoutFound = true
		}
	}
	if !capFound {
		t.Error("CAPABILITY command not sent")
	}
	if !logoutFound {
		t.Error("LOGOUT command not sent")
	}
}

func TestIMAP_ModulesRegistered(t *testing.T) {
	_, ok := Get("imap")
	if !ok {
		t.Fatal("imap module not registered")
	}
	_, ok = Get("imaps")
	if !ok {
		t.Fatal("imaps module not registered")
	}
}
