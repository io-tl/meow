package packet

import (
	"encoding/binary"
	"net"
	"testing"

	"meow/synscan/pkg/types"
)

// buildTestPacket builds a minimal IP+TCP packet for testing
func buildTestPacket(srcIP net.IP, srcPort, dstPort uint16, flags uint8) []byte {
	pkt := make([]byte, 40) // 20 IP + 20 TCP

	// IP header
	pkt[0] = 0x45                            // Version 4, IHL 5
	binary.BigEndian.PutUint16(pkt[2:4], 40) // Total length
	pkt[8] = 64                              // TTL
	pkt[9] = 6                               // TCP protocol
	copy(pkt[12:16], srcIP.To4())

	// TCP header at offset 20
	binary.BigEndian.PutUint16(pkt[20:22], srcPort)
	binary.BigEndian.PutUint16(pkt[22:24], dstPort)
	pkt[32] = 5 << 4 // Data offset
	pkt[33] = flags  // TCP flags

	return pkt
}

func TestParseTCPResponse_SYNACK(t *testing.T) {
	srcIP := net.ParseIP("10.0.0.2").To4()
	pkt := buildTestPacket(srcIP, 80, 40000, 0x12)

	resp, ok := ParseTCPResponse(pkt, 40000)
	if !ok {
		t.Fatal("expected valid parse")
	}
	if !resp.SrcIP.Equal(srcIP) {
		t.Errorf("src IP: expected %s, got %s", srcIP, resp.SrcIP)
	}
	if resp.SrcPort != 80 {
		t.Errorf("src port: expected 80, got %d", resp.SrcPort)
	}
	if resp.DstPort != 40000 {
		t.Errorf("dst port: expected 40000, got %d", resp.DstPort)
	}
	if !resp.SYN {
		t.Error("SYN flag should be set")
	}
	if !resp.ACK {
		t.Error("ACK flag should be set")
	}
	if resp.RST {
		t.Error("RST flag should not be set")
	}
	if resp.Flags != 0x12 {
		t.Errorf("flags: expected 0x12, got 0x%02x", resp.Flags)
	}
}

func TestParseTCPResponse_RST(t *testing.T) {
	srcIP := net.ParseIP("10.0.0.2").To4()
	pkt := buildTestPacket(srcIP, 80, 40000, 0x04)

	resp, ok := ParseTCPResponse(pkt, 40000)
	if !ok {
		t.Fatal("expected valid parse")
	}
	if resp.RST != true {
		t.Error("RST flag should be set")
	}
	if resp.SYN {
		t.Error("SYN flag should not be set")
	}
	if resp.ACK {
		t.Error("ACK flag should not be set")
	}
}

func TestParseTCPResponse_WrongDstPort(t *testing.T) {
	pkt := buildTestPacket(net.ParseIP("10.0.0.2").To4(), 80, 40000, 0x12)

	// Looking for port 50000, packet has 40000
	_, ok := ParseTCPResponse(pkt, 50000)
	if ok {
		t.Error("expected false when dst port doesn't match")
	}
}

func TestParseTCPResponse_TooShort(t *testing.T) {
	// Less than 40 bytes
	pkt := make([]byte, 39)
	_, ok := ParseTCPResponse(pkt, 40000)
	if ok {
		t.Error("expected false for packet < 40 bytes")
	}
}

func TestParseTCPResponse_MinimumValid(t *testing.T) {
	// Exactly 40 bytes
	pkt := buildTestPacket(net.ParseIP("10.0.0.1").To4(), 80, 40000, 0x12)
	resp, ok := ParseTCPResponse(pkt, 40000)
	if !ok {
		t.Fatal("expected valid parse for 40-byte packet")
	}
	if resp.SrcPort != 80 {
		t.Errorf("src port: expected 80, got %d", resp.SrcPort)
	}
}

func TestParseTCPResponse_IPHeaderLargerThan20(t *testing.T) {
	// IP header with options: IHL=6 (24 bytes), total packet = 24 + 20 = 44
	pkt := make([]byte, 44)
	pkt[0] = 0x46 // Version 4, IHL 6
	binary.BigEndian.PutUint16(pkt[2:4], 44)
	pkt[8] = 64
	pkt[9] = 6
	copy(pkt[12:16], net.ParseIP("10.0.0.5").To4())

	// TCP header at offset 24 (IHL*4)
	binary.BigEndian.PutUint16(pkt[24:26], 443)   // src port
	binary.BigEndian.PutUint16(pkt[26:28], 50000) // dst port
	pkt[36] = 5 << 4
	pkt[37] = 0x12 // SYN+ACK

	resp, ok := ParseTCPResponse(pkt, 50000)
	if !ok {
		t.Fatal("expected valid parse with IP options")
	}
	if resp.SrcPort != 443 {
		t.Errorf("src port: expected 443, got %d", resp.SrcPort)
	}
}

func TestParseTCPResponse_TCPHeaderTooShort(t *testing.T) {
	// IHL=5 but packet truncated before TCP header completes
	pkt := make([]byte, 38) // 20 IP + 18 TCP (needs 20)
	pkt[0] = 0x45
	_, ok := ParseTCPResponse(pkt, 40000)
	if ok {
		t.Error("expected false when TCP header is truncated")
	}
}

func TestParseTCPResponse_ZeroFlags(t *testing.T) {
	pkt := buildTestPacket(net.ParseIP("10.0.0.1").To4(), 80, 40000, 0x00)
	resp, ok := ParseTCPResponse(pkt, 40000)
	if !ok {
		t.Fatal("expected valid parse with zero flags")
	}
	if resp.SYN || resp.ACK || resp.RST {
		t.Error("no flags should be set")
	}
}

// --- GetPortState ---

func TestGetPortState_Open(t *testing.T) {
	resp := &TCPResponse{SYN: true, ACK: true}
	if resp.GetPortState() != types.PortOpen {
		t.Errorf("SYN+ACK should be PortOpen, got %s", resp.GetPortState())
	}
}

func TestGetPortState_Closed(t *testing.T) {
	resp := &TCPResponse{RST: true}
	if resp.GetPortState() != types.PortClosed {
		t.Errorf("RST should be PortClosed, got %s", resp.GetPortState())
	}
}

func TestGetPortState_Filtered(t *testing.T) {
	resp := &TCPResponse{SYN: false, ACK: false, RST: false}
	if resp.GetPortState() != types.PortFiltered {
		t.Errorf("no flags should be PortFiltered, got %s", resp.GetPortState())
	}
}

func TestGetPortState_SYNOnly(t *testing.T) {
	resp := &TCPResponse{SYN: true, ACK: false}
	// SYN without ACK is not PortOpen
	if resp.GetPortState() == types.PortOpen {
		t.Error("SYN without ACK should not be PortOpen")
	}
}

func TestGetPortState_ACKOnly(t *testing.T) {
	resp := &TCPResponse{SYN: false, ACK: true}
	// ACK only is not PortOpen
	if resp.GetPortState() == types.PortOpen {
		t.Error("ACK without SYN should not be PortOpen")
	}
}

func TestGetPortState_RSTWithSYN(t *testing.T) {
	// RST takes precedence even with SYN set (edge case)
	resp := &TCPResponse{SYN: true, ACK: true, RST: true}
	// SYN+ACK check is first, so this is PortOpen
	state := resp.GetPortState()
	if state != types.PortOpen {
		t.Errorf("SYN+ACK+RST: expected PortOpen (SYN+ACK checked first), got %s", state)
	}
}

// --- Integration: Forge + Parse ---

func TestForgeAndParse_Roundtrip(t *testing.T) {
	srcIP := net.ParseIP("192.168.1.10")
	dstIP := net.ParseIP("192.168.1.20")
	f := NewForger(srcIP)

	pkt, err := f.ForgeSYN(45000, dstIP, 80)
	if err != nil {
		t.Fatalf("forge error: %v", err)
	}

	// The packet is a SYN from srcIP:45000 to dstIP:80
	// Parsing expects this as a response, so we parse from perspective of receiver
	// Source in packet = srcIP, srcPort=45000, dstPort=80
	resp, ok := ParseTCPResponse(pkt, 80)
	if !ok {
		t.Fatal("expected valid parse of forged packet")
	}
	if !resp.SrcIP.Equal(srcIP.To4()) {
		t.Errorf("parsed src IP: expected %s, got %s", srcIP, resp.SrcIP)
	}
	if resp.SrcPort != 45000 {
		t.Errorf("parsed src port: expected 45000, got %d", resp.SrcPort)
	}
	if resp.DstPort != 80 {
		t.Errorf("parsed dst port: expected 80, got %d", resp.DstPort)
	}
	if !resp.SYN {
		t.Error("SYN flag should be set in forged SYN packet")
	}
	if resp.ACK {
		t.Error("ACK flag should not be set in forged SYN packet")
	}
}
