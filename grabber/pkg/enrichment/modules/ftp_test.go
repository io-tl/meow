package modules

import (
	"bufio"
	"fmt"
	"net"
	"testing"
	"time"
)

func TestScanFTP_FullServer(t *testing.T) {
	host, port := startTestTCPServer(t, func(conn net.Conn) {
		reader := bufio.NewReader(conn)

		// Send welcome banner.
		fmt.Fprintf(conn, "220 Welcome to Test FTP Server\r\n")

		// Read FEAT command.
		line, _ := reader.ReadString('\n')
		if line == "" {
			return
		}

		// Respond with features.
		fmt.Fprintf(conn, "211-Features:\r\n")
		fmt.Fprintf(conn, " AUTH TLS\r\n")
		fmt.Fprintf(conn, " PASV\r\n")
		fmt.Fprintf(conn, " UTF8\r\n")
		fmt.Fprintf(conn, "211 End\r\n")

		// Read USER anonymous.
		line, _ = reader.ReadString('\n')
		if line == "" {
			return
		}
		fmt.Fprintf(conn, "331 Please specify the password.\r\n")

		// Read PASS.
		line, _ = reader.ReadString('\n')
		if line == "" {
			return
		}
		fmt.Fprintf(conn, "230 Login successful.\r\n")

		// Read QUIT.
		reader.ReadString('\n')
	})

	result, err := scanFTP(host, port, 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Banner == "" {
		t.Error("Banner should not be empty")
	}
	if result.WelcomeMessage == "" {
		t.Error("WelcomeMessage should not be empty")
	}
	if !result.SupportsTLS {
		t.Error("SupportsTLS = false, want true")
	}
	if !result.SupportsPassive {
		t.Error("SupportsPassive = false, want true")
	}
	if !result.AnonymousLogin {
		t.Error("AnonymousLogin = false, want true")
	}
	if len(result.Features) == 0 {
		t.Error("Features should not be empty")
	}
	if result.Error != "" {
		t.Errorf("Error = %q, want empty", result.Error)
	}
}

func TestScanFTP_AnonymousRefused(t *testing.T) {
	host, port := startTestTCPServer(t, func(conn net.Conn) {
		reader := bufio.NewReader(conn)

		fmt.Fprintf(conn, "220 Secure FTP Server\r\n")

		// Read FEAT.
		reader.ReadString('\n')
		fmt.Fprintf(conn, "211-Features:\r\n")
		fmt.Fprintf(conn, " PASV\r\n")
		fmt.Fprintf(conn, "211 End\r\n")

		// Read USER anonymous.
		reader.ReadString('\n')
		fmt.Fprintf(conn, "530 Login incorrect.\r\n")

		// Read QUIT.
		reader.ReadString('\n')
	})

	result, err := scanFTP(host, port, 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.AnonymousLogin {
		t.Error("AnonymousLogin = true, want false")
	}
	if result.Banner == "" {
		t.Error("Banner should not be empty")
	}
}

func TestScanFTP_FEATNotSupported(t *testing.T) {
	host, port := startTestTCPServer(t, func(conn net.Conn) {
		reader := bufio.NewReader(conn)

		fmt.Fprintf(conn, "220 Minimal FTP Server\r\n")

		// Read FEAT command, respond with error then close.
		reader.ReadString('\n')
		fmt.Fprintf(conn, "500 Unknown command.\r\n")

		// Close connection so the FEAT read loop terminates.
	})

	result, err := scanFTP(host, port, 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Banner == "" {
		t.Error("Banner should not be empty")
	}
	// The 500 response is not a 211 feature line, but it doesn't start with "211",
	// so it should NOT be added to features either. The server closes after the 500
	// so the feature loop terminates via read error.
	if result.SupportsTLS {
		t.Error("SupportsTLS should be false")
	}
	if result.SupportsPassive {
		t.Error("SupportsPassive should be false")
	}
}
