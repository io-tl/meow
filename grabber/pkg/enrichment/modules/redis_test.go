package modules

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func TestScanRedis_InfoResponse(t *testing.T) {
	infoData := "# Server\r\nredis_version:7.0.0\r\nredis_mode:standalone\r\nos:Linux\r\n"
	host, port := startTestTCPServer(t, func(conn net.Conn) {
		buf := make([]byte, 100)
		conn.Read(buf) // Read INFO\r\n
		// Send bulk string response
		fmt.Fprintf(conn, "$%d\r\n%s", len(infoData), infoData)
	})

	result, err := scanRedis(host, port, 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Protocol != "redis" {
		t.Errorf("Protocol = %q", result.Protocol)
	}
	if result.Version != "7.0.0" {
		t.Errorf("Version = %q, want %q", result.Version, "7.0.0")
	}
	if result.Mode != "standalone" {
		t.Errorf("Mode = %q, want %q", result.Mode, "standalone")
	}
	if result.Info["redis_version"] != "7.0.0" {
		t.Errorf("Info[redis_version] = %q", result.Info["redis_version"])
	}
}

func TestScanRedis_NOAUTH(t *testing.T) {
	host, port := startTestTCPServer(t, func(conn net.Conn) {
		buf := make([]byte, 100)
		conn.Read(buf)
		conn.Write([]byte("-NOAUTH Authentication required.\r\n"))
	})

	result, err := scanRedis(host, port, 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Error != "Authentication required" {
		t.Errorf("Error = %q, want %q", result.Error, "Authentication required")
	}
}

func TestScanRedis_InfoResponseFragmented(t *testing.T) {
	infoData := "# Server\r\nredis_version:7.0.1\r\nredis_mode:cluster\r\n"
	host, port := startTestTCPServer(t, func(conn net.Conn) {
		buf := make([]byte, 100)
		conn.Read(buf)
		fmt.Fprintf(conn, "$%d\r\n", len(infoData))
		conn.Write([]byte(infoData[:12]))
		time.Sleep(10 * time.Millisecond)
		conn.Write([]byte(infoData[12:]))
		conn.Write([]byte("\r\n"))
	})

	result, err := scanRedis(host, port, 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Version != "7.0.1" {
		t.Errorf("Version = %q, want %q", result.Version, "7.0.1")
	}
	if result.Mode != "cluster" {
		t.Errorf("Mode = %q, want %q", result.Mode, "cluster")
	}
}

func TestScanRedis_ERR(t *testing.T) {
	host, port := startTestTCPServer(t, func(conn net.Conn) {
		buf := make([]byte, 100)
		conn.Read(buf)
		conn.Write([]byte("-ERR unknown command\r\n"))
	})

	result, err := scanRedis(host, port, 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result.Error, "ERR unknown command") {
		t.Errorf("Error = %q, want contains 'ERR unknown command'", result.Error)
	}
}

func TestRedis_ModuleRegistered(t *testing.T) {
	mod, ok := Get("redis")
	if !ok {
		t.Fatal("redis module not registered")
	}
	if !mod.ShouldEnrich() {
		t.Error("ShouldEnrich() = false")
	}
}
