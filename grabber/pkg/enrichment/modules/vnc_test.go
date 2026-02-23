package modules

import (
	"net"
	"testing"
	"time"
)

func TestScanVNC_NoAuth(t *testing.T) {
	host, port := startTestTCPServer(t, func(conn net.Conn) {
		// Send RFB version
		conn.Write([]byte("RFB 003.008\n"))
		// Read client version
		buf := make([]byte, 12)
		conn.Read(buf)
		// Send security types: 1 type, type=1 (None)
		conn.Write([]byte{1, 1})
		// Read security type selection
		conn.Read(buf[:1])
		// Send security result: OK (0)
		conn.Write([]byte{0, 0, 0, 0})
		// Read ClientInit
		conn.Read(buf[:1])
		// Send minimal ServerInit (24 bytes)
		serverInit := make([]byte, 24)
		serverInit[0] = 0x03 // width high
		serverInit[1] = 0x20 // width low = 800
		serverInit[2] = 0x02 // height high
		serverInit[3] = 0x58 // height low = 600
		// name length = 4
		serverInit[23] = 4
		conn.Write(serverInit)
		conn.Write([]byte("Test"))
		// Don't send framebuffer data, just close
	})

	mod, ok := Get("vnc")
	if !ok {
		t.Fatal("vnc not registered")
	}
	iresult, err := mod.Scan(host, port)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	result := iresult.(*VNCResult)
	if result.Version != "RFB 003.008" {
		t.Errorf("Version = %q, want %q", result.Version, "RFB 003.008")
	}
	if result.Authentication {
		t.Error("Authentication = true, want false (None auth)")
	}
	if len(result.SecurityTypes) == 0 {
		t.Error("SecurityTypes empty")
	}
}

func TestScanVNC_VNCAuth(t *testing.T) {
	host, port := startTestTCPServer(t, func(conn net.Conn) {
		conn.Write([]byte("RFB 003.008\n"))
		buf := make([]byte, 12)
		conn.Read(buf)
		// Security types: 1 type, type=2 (VNC Authentication)
		conn.Write([]byte{1, 2})
	})

	mod, _ := Get("vnc")
	iresult, err := mod.Scan(host, port)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	result := iresult.(*VNCResult)
	if !result.Authentication {
		t.Error("Authentication = false, want true")
	}
}

func TestScanVNC_ZeroSecurityTypes(t *testing.T) {
	host, port := startTestTCPServer(t, func(conn net.Conn) {
		conn.Write([]byte("RFB 003.008\n"))
		buf := make([]byte, 12)
		conn.Read(buf)
		// 0 security types
		conn.Write([]byte{0})
	})

	mod, _ := Get("vnc")
	iresult, _ := mod.Scan(host, port)
	result := iresult.(*VNCResult)
	// Should not panic
	if len(result.SecurityTypes) != 0 {
		t.Errorf("SecurityTypes = %v, want empty", result.SecurityTypes)
	}
}

func TestScanVNC_NotRFB(t *testing.T) {
	host, port := startTestTCPServer(t, func(conn net.Conn) {
		conn.Write([]byte("NOT RFB\n"))
	})

	mod, _ := Get("vnc")
	iresult, err := mod.Scan(host, port)
	if err == nil {
		t.Log("expected error for non-RFB")
	}
	result := iresult.(*VNCResult)
	if result.Error == "" {
		t.Error("Error should be set for non-RFB")
	}
}

func TestVNC_ModuleRegistered(t *testing.T) {
	mod, ok := Get("vnc")
	if !ok {
		t.Fatal("vnc not registered")
	}
	if mod.DefaultTimeout() != 15*time.Second {
		t.Errorf("DefaultTimeout = %v, want 15s", mod.DefaultTimeout())
	}
	// Check alias
	_, ok = Get("rfb")
	if !ok {
		t.Fatal("rfb alias not registered")
	}
}
