package modules

import (
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"
)

func TestBuildMinecraftHandshake_Normal(t *testing.T) {
	result := buildMinecraftHandshake("localhost", 25565)
	if len(result) == 0 {
		t.Fatal("empty handshake")
	}
	// First byte is packet length, should be non-zero
	if result[0] == 0 {
		t.Error("packet length is 0")
	}
}

func TestBuildMinecraftHandshake_LongHost(t *testing.T) {
	longHost := strings.Repeat("a", 300)
	result := buildMinecraftHandshake(longHost, 25565)
	if len(result) == 0 {
		t.Fatal("empty handshake")
	}
	// The host should be truncated to 255 bytes
	// Find the host length byte in the packet
	// Packet structure: [length prefix] [0x00=packetID] [0x04=protocol] [hostLen] [host...] [port] [0x01]
	// Check the packet doesn't contain more than 255 bytes of host
	if len(result) > 300 {
		t.Errorf("packet too long: %d bytes, host should be truncated to 255", len(result))
	}
}

func TestBuildMinecraftHandshake_VarIntLength(t *testing.T) {
	// For a long host, the payload will be > 127 bytes, requiring 2-byte VarInt length
	host := strings.Repeat("x", 200)
	result := buildMinecraftHandshake(host, 25565)
	if len(result) == 0 {
		t.Fatal("empty handshake")
	}
	// The first byte should have bit 7 set (0x80) for 2-byte VarInt
	if result[0]&0x80 == 0 {
		t.Errorf("expected 2-byte VarInt for long payload, first byte = 0x%02x", result[0])
	}
}

func TestBuildMinecraftHandshake_PortZero(t *testing.T) {
	result := buildMinecraftHandshake("host", 0)
	if len(result) == 0 {
		t.Fatal("empty handshake")
	}
}

func TestScanMinecraft_StatusResponse(t *testing.T) {
	statusJSON := `{"version":{"name":"1.20.4","protocol":765},"players":{"max":20,"online":5},"description":{"text":"A Minecraft Server"}}`

	host, port := startTestTCPServer(t, func(conn net.Conn) {
		// Read handshake + status request
		buf := make([]byte, 512)
		conn.Read(buf)

		// Build response: packet length + packet ID (0x00) + JSON string
		jsonBytes := []byte(statusJSON)
		// VarInt for JSON length
		jsonLen := len(jsonBytes)
		// Build the response packet
		var resp []byte
		// Packet ID 0x00
		resp = append(resp, 0x00)
		// String length as VarInt
		resp = append(resp, byte(jsonLen&0x7F|0x80), byte(jsonLen>>7))
		resp = append(resp, jsonBytes...)
		// Packet length as VarInt
		pktLen := len(resp)
		var pkt []byte
		if pktLen < 128 {
			pkt = append([]byte{byte(pktLen)}, resp...)
		} else {
			pkt = append([]byte{byte(pktLen&0x7F | 0x80), byte(pktLen >> 7)}, resp...)
		}
		conn.Write(pkt)
	})

	result, err := scanMinecraft(host, port, 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Protocol != "minecraft" {
		t.Errorf("Protocol = %q", result.Protocol)
	}
	if result.Version != "1.20.4" {
		t.Errorf("Version = %q, want %q", result.Version, "1.20.4")
	}
	if result.MOTD != "A Minecraft Server" {
		t.Errorf("MOTD = %q, want %q", result.MOTD, "A Minecraft Server")
	}
}

func TestMinecraftResult_JSONMarshal(t *testing.T) {
	r := MinecraftResult{
		Protocol: "minecraft",
		Version:  "1.20.4",
		MOTD:     "test",
	}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(data), "minecraft") {
		t.Error("expected 'minecraft' in JSON")
	}
}

func TestMinecraft_ModuleRegistered(t *testing.T) {
	_, ok := Get("minecraft")
	if !ok {
		t.Fatal("minecraft not registered")
	}
}
