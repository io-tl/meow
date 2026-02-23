package modules

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestScanMongoDB_ValidResponse(t *testing.T) {
	host, port := startTestTCPServer(t, func(conn net.Conn) {
		// Read the probe
		buf := make([]byte, 256)
		conn.Read(buf)

		// Build a valid MongoDB OP_REPLY (opcode=1)
		resp := make([]byte, 36)
		binary.LittleEndian.PutUint32(resp[0:4], 36)  // messageLength
		binary.LittleEndian.PutUint32(resp[4:8], 2)    // requestID
		binary.LittleEndian.PutUint32(resp[8:12], 1)   // responseTo
		binary.LittleEndian.PutUint32(resp[12:16], 1)  // opCode = OP_REPLY
		binary.LittleEndian.PutUint32(resp[16:20], 0)  // responseFlags
		binary.LittleEndian.PutUint64(resp[20:28], 0)  // cursorID
		binary.LittleEndian.PutUint32(resp[28:32], 0)  // startingFrom
		binary.LittleEndian.PutUint32(resp[32:36], 0)  // numberReturned
		conn.Write(resp)
	})

	result, err := scanMongoDB(host, port, 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Protocol != "mongodb" {
		t.Errorf("Protocol = %q", result.Protocol)
	}
	if result.Version != "detected" {
		t.Errorf("Version = %q, want %q", result.Version, "detected")
	}
}

func TestScanMongoDB_InvalidOpCode(t *testing.T) {
	host, port := startTestTCPServer(t, func(conn net.Conn) {
		buf := make([]byte, 256)
		conn.Read(buf)

		resp := make([]byte, 16)
		binary.LittleEndian.PutUint32(resp[0:4], 16)   // messageLength
		binary.LittleEndian.PutUint32(resp[12:16], 99)  // invalid opCode
		conn.Write(resp)
	})

	result, err := scanMongoDB(host, port, 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Error == "" {
		t.Error("expected Error to be set for invalid opCode")
	}
}

func TestScanMongoDB_TruncatedResponse(t *testing.T) {
	host, port := startTestTCPServer(t, func(conn net.Conn) {
		buf := make([]byte, 256)
		conn.Read(buf)
		// Send only 4 bytes - not enough for a full header
		conn.Write([]byte{0x04, 0x00, 0x00, 0x00})
	})

	result, err := scanMongoDB(host, port, 3*time.Second)
	// Should not panic
	if err != nil && result == nil {
		t.Fatal("result should not be nil even on error")
	}
}

func TestMongoDB_ModuleRegistered(t *testing.T) {
	mod, ok := Get("mongodb")
	if !ok {
		t.Fatal("mongodb not registered")
	}
	if mod.Name() != "mongodb" {
		t.Errorf("Name() = %q", mod.Name())
	}
	// Check alias
	_, ok = Get("mongo")
	if !ok {
		t.Fatal("mongo alias not registered")
	}
}
