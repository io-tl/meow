package modules

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"image/png"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestScanX11_NonX11Banner(t *testing.T) {
	host, port := startTestTCPServer(t, func(conn net.Conn) {
		buf := make([]byte, 12)
		_, _ = io.ReadFull(conn, buf)
		_, _ = conn.Write([]byte("Hello welcome on this challenge!!!\n"))
	})

	result, err := scanX11(host, port, 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Banner == "" {
		t.Fatal("Banner is empty")
	}
	if !strings.Contains(result.Banner, "Hello welcome") {
		t.Fatalf("Banner = %q", result.Banner)
	}
	if result.Error != "non-X11 service responded" {
		t.Fatalf("Error = %q", result.Error)
	}
}

func TestScanX11_Screenshot(t *testing.T) {
	host, port := startTestTCPServer(t, func(conn net.Conn) {
		setupReq := make([]byte, 12)
		_, _ = io.ReadFull(conn, setupReq)

		body := buildX11SetupSuccessBody()
		header := make([]byte, 8)
		header[0] = 1
		binary.LittleEndian.PutUint16(header[2:4], 11)
		binary.LittleEndian.PutUint16(header[4:6], 0)
		binary.LittleEndian.PutUint16(header[6:8], uint16(len(body)/4))
		_, _ = conn.Write(append(header, body...))

		getImageReq := make([]byte, 20)
		_, _ = io.ReadFull(conn, getImageReq)
		if getImageReq[0] != 73 {
			t.Fatalf("opcode = %d, want 73", getImageReq[0])
		}

		pixels := []byte{
			0x00, 0x00, 0xff, 0x00,
			0x00, 0xff, 0x00, 0x00,
		}
		reply := make([]byte, 32+len(pixels))
		reply[0] = 1
		reply[1] = 24
		binary.LittleEndian.PutUint32(reply[4:8], uint32(len(pixels)/4))
		binary.LittleEndian.PutUint32(reply[8:12], 33)
		copy(reply[32:], pixels)
		_, _ = conn.Write(reply)
	})

	result, err := scanX11(host, port, 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Error != "" {
		t.Fatalf("Error = %q", result.Error)
	}
	if result.Width != 2 || result.Height != 1 {
		t.Fatalf("size = %dx%d", result.Width, result.Height)
	}
	if !strings.HasPrefix(result.Screenshot, "data:image/png;base64,") {
		t.Fatalf("Screenshot prefix invalid: %q", result.Screenshot)
	}

	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(result.Screenshot, "data:image/png;base64,"))
	if err != nil {
		t.Fatalf("decode screenshot: %v", err)
	}
	img, err := png.Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("png decode: %v", err)
	}
	if img.Bounds().Dx() != 2 || img.Bounds().Dy() != 1 {
		t.Fatalf("decoded size = %dx%d", img.Bounds().Dx(), img.Bounds().Dy())
	}
}

func buildX11SetupSuccessBody() []byte {
	vendor := []byte("Test")
	body := make([]byte, 24)
	binary.LittleEndian.PutUint32(body[0:4], 1234)
	binary.LittleEndian.PutUint16(body[12:14], 65535)
	binary.LittleEndian.PutUint16(body[16:18], uint16(len(vendor)))
	body[20] = 1
	body[21] = 1
	body[22] = 'l'
	body[23] = 0

	body = append(body, vendor...)

	body = append(body,
		24, 32, 32, 0, 0, 0, 0, 0,
	)

	screen := make([]byte, 40)
	binary.LittleEndian.PutUint32(screen[0:4], 1)
	binary.LittleEndian.PutUint16(screen[20:22], 2)
	binary.LittleEndian.PutUint16(screen[22:24], 1)
	binary.LittleEndian.PutUint32(screen[32:36], 33)
	screen[38] = 24
	screen[39] = 1
	body = append(body, screen...)

	depth := make([]byte, 8)
	depth[0] = 24
	binary.LittleEndian.PutUint16(depth[2:4], 1)
	body = append(body, depth...)

	visual := make([]byte, 24)
	binary.LittleEndian.PutUint32(visual[0:4], 33)
	visual[4] = 4
	visual[5] = 8
	binary.LittleEndian.PutUint16(visual[6:8], 256)
	binary.LittleEndian.PutUint32(visual[8:12], 0x00ff0000)
	binary.LittleEndian.PutUint32(visual[12:16], 0x0000ff00)
	binary.LittleEndian.PutUint32(visual[16:20], 0x000000ff)
	body = append(body, visual...)

	return body
}
