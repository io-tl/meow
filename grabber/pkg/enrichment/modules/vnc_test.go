package modules

import (
	"encoding/base64"
	"image/png"
	"net"
	"strings"
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

func TestScanVNC_NoAuthCapturesScreenshot(t *testing.T) {
	host, port := startTestTCPServer(t, func(conn net.Conn) {
		conn.Write([]byte("RFB 003.008\n"))

		buf := make([]byte, 12)
		conn.Read(buf)

		conn.Write([]byte{1, 1})
		conn.Read(buf[:1])
		conn.Write([]byte{0, 0, 0, 0})
		conn.Read(buf[:1])

		serverInit := make([]byte, 24)
		serverInit[0] = 0x00
		serverInit[1] = 0x02
		serverInit[2] = 0x00
		serverInit[3] = 0x01
		serverInit[4] = 32
		serverInit[5] = 24
		serverInit[6] = 0
		serverInit[7] = 1
		serverInit[8] = 0x00
		serverInit[9] = 0xff
		serverInit[10] = 0x00
		serverInit[11] = 0xff
		serverInit[12] = 0x00
		serverInit[13] = 0xff
		serverInit[14] = 16
		serverInit[15] = 8
		serverInit[16] = 0
		serverInit[23] = 4
		conn.Write(serverInit)
		conn.Write([]byte("Test"))

		req := make([]byte, 10)
		conn.Read(req)

		framebufferUpdate := []byte{
			0, 0, 0, 1,
			0, 0, 0, 0, 0, 2, 0, 1, 0, 0, 0, 0,
			0x00, 0x00, 0xff, 0x00,
			0x00, 0xff, 0x00, 0x00,
		}
		conn.Write(framebufferUpdate)
	})

	mod, _ := Get("vnc")
	iresult, err := mod.Scan(host, port)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	result := iresult.(*VNCResult)
	if result.ScreenshotFormat != "png" {
		t.Fatalf("ScreenshotFormat = %q, want png", result.ScreenshotFormat)
	}
	if !strings.HasPrefix(result.Screenshot, "data:image/png;base64,") {
		t.Fatalf("Screenshot prefix invalid: %q", result.Screenshot)
	}

	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(result.Screenshot, "data:image/png;base64,"))
	if err != nil {
		t.Fatalf("decode screenshot: %v", err)
	}
	img, err := png.Decode(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatalf("png decode: %v", err)
	}
	if img.Bounds().Dx() != 2 || img.Bounds().Dy() != 1 {
		t.Fatalf("image bounds = %v, want 2x1", img.Bounds())
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
