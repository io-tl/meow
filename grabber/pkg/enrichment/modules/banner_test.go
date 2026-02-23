package modules

import (
	"net"
	"strconv"
	"testing"
	"time"
)

// startTestTCPServer starts a TCP server on a random port that calls handler for
// one accepted connection. The listener is closed via t.Cleanup. Returns the
// host and numeric port so callers can pass them directly to scanXXX functions.
func startTestTCPServer(t *testing.T, handler func(net.Conn)) (string, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		handler(conn)
	}()
	t.Cleanup(func() { ln.Close() })
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	return host, port
}

// startTestUDPServer starts a UDP server on a random port that calls handler.
// The connection is closed via t.Cleanup. Returns the host and numeric port.
func startTestUDPServer(t *testing.T, handler func(*net.UDPConn)) (string, int) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	udpConn := pc.(*net.UDPConn)
	go handler(udpConn)
	t.Cleanup(func() { pc.Close() })
	host, portStr, _ := net.SplitHostPort(pc.LocalAddr().String())
	port, _ := strconv.Atoi(portStr)
	return host, port
}

func TestScanBanner_SSHBanner(t *testing.T) {
	banner := "SSH-2.0-OpenSSH_8.9\r\n"
	host, port := startTestTCPServer(t, func(conn net.Conn) {
		conn.Write([]byte(banner))
	})

	result, err := scanBanner(host, port, 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Protocol != "banner" {
		t.Errorf("Protocol = %q, want %q", result.Protocol, "banner")
	}
	if result.Banner != banner {
		t.Errorf("Banner = %q, want %q", result.Banner, banner)
	}
	if result.Length <= 0 {
		t.Errorf("Length = %d, want > 0", result.Length)
	}
	if result.Error != "" {
		t.Errorf("Error = %q, want empty", result.Error)
	}
}

func TestScanBanner_ServerClosesImmediately(t *testing.T) {
	host, port := startTestTCPServer(t, func(conn net.Conn) {
		// Close immediately without sending anything.
	})

	result, err := scanBanner(host, port, 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Banner != "" {
		t.Errorf("Banner = %q, want empty", result.Banner)
	}
	if result.Length != 0 {
		t.Errorf("Length = %d, want 0", result.Length)
	}
}

func TestScanBanner_BinaryData(t *testing.T) {
	binaryPayload := []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0x80, 0x7F}
	host, port := startTestTCPServer(t, func(conn net.Conn) {
		conn.Write(binaryPayload)
	})

	result, err := scanBanner(host, port, 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Length != len(binaryPayload) {
		t.Errorf("Length = %d, want %d", result.Length, len(binaryPayload))
	}
	if result.Banner != string(binaryPayload) {
		t.Errorf("Banner bytes mismatch")
	}
}
