package packet

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestNewForger(t *testing.T) {
	srcIP := net.ParseIP("192.168.1.100")
	f := NewForger(srcIP)
	if f == nil {
		t.Fatal("NewForger returned nil")
	}
	if !f.GetSourceIP().Equal(srcIP.To4()) {
		t.Errorf("source IP: expected %s, got %s", srcIP, f.GetSourceIP())
	}
}

func TestForgeSYN_PacketLength(t *testing.T) {
	f := NewForger(net.ParseIP("10.0.0.1"))
	pkt, err := f.ForgeSYN(40000, net.ParseIP("10.0.0.2"), 80)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// IP header (20) + TCP header (20) = 40 bytes
	if len(pkt) != 40 {
		t.Errorf("expected 40 bytes, got %d", len(pkt))
	}
}

func TestForgeSYN_IPHeader(t *testing.T) {
	srcIP := net.ParseIP("10.0.0.1")
	dstIP := net.ParseIP("10.0.0.2")
	f := NewForger(srcIP)
	pkt, _ := f.ForgeSYN(40000, dstIP, 80)

	// Version + IHL
	versionIHL := pkt[0]
	version := versionIHL >> 4
	ihl := versionIHL & 0x0F
	if version != 4 {
		t.Errorf("IP version: expected 4, got %d", version)
	}
	if ihl != 5 {
		t.Errorf("IHL: expected 5, got %d", ihl)
	}

	// Total length = 40
	totalLen := binary.BigEndian.Uint16(pkt[2:4])
	if totalLen != 40 {
		t.Errorf("total length: expected 40, got %d", totalLen)
	}

	// TTL = 64
	if pkt[8] != 64 {
		t.Errorf("TTL: expected 64, got %d", pkt[8])
	}

	// Protocol = 6 (TCP)
	if pkt[9] != 6 {
		t.Errorf("protocol: expected 6 (TCP), got %d", pkt[9])
	}

	// Source IP
	gotSrcIP := net.IP(pkt[12:16])
	if !gotSrcIP.Equal(srcIP.To4()) {
		t.Errorf("source IP: expected %s, got %s", srcIP, gotSrcIP)
	}

	// Destination IP
	gotDstIP := net.IP(pkt[16:20])
	if !gotDstIP.Equal(dstIP.To4()) {
		t.Errorf("destination IP: expected %s, got %s", dstIP, gotDstIP)
	}
}

func TestForgeSYN_TCPHeader(t *testing.T) {
	f := NewForger(net.ParseIP("10.0.0.1"))
	pkt, _ := f.ForgeSYN(40000, net.ParseIP("10.0.0.2"), 80)

	tcp := pkt[20:] // TCP header starts at byte 20

	// Source port
	srcPort := binary.BigEndian.Uint16(tcp[0:2])
	if srcPort != 40000 {
		t.Errorf("TCP src port: expected 40000, got %d", srcPort)
	}

	// Destination port
	dstPort := binary.BigEndian.Uint16(tcp[2:4])
	if dstPort != 80 {
		t.Errorf("TCP dst port: expected 80, got %d", dstPort)
	}

	// Data offset (byte 12, upper nibble) = 5 (20 bytes / 4)
	dataOffset := tcp[12] >> 4
	if dataOffset != 5 {
		t.Errorf("TCP data offset: expected 5, got %d", dataOffset)
	}

	// Flags: only SYN (0x02)
	flags := tcp[13]
	if flags != 0x02 {
		t.Errorf("TCP flags: expected 0x02 (SYN), got 0x%02x", flags)
	}

	// Window size = 65535
	window := binary.BigEndian.Uint16(tcp[14:16])
	if window != 65535 {
		t.Errorf("TCP window: expected 65535, got %d", window)
	}

	// Urgent pointer = 0
	urgent := binary.BigEndian.Uint16(tcp[18:20])
	if urgent != 0 {
		t.Errorf("TCP urgent pointer: expected 0, got %d", urgent)
	}
}

func TestForgeSYN_TCPChecksum_NonZero(t *testing.T) {
	f := NewForger(net.ParseIP("192.168.1.1"))
	pkt, _ := f.ForgeSYN(50000, net.ParseIP("192.168.1.2"), 443)

	tcp := pkt[20:]
	checksum := binary.BigEndian.Uint16(tcp[16:18])
	if checksum == 0 {
		t.Error("TCP checksum should not be zero")
	}
}

func TestForgeSYN_DifferentPortsDifferentPackets(t *testing.T) {
	f := NewForger(net.ParseIP("10.0.0.1"))
	pkt1, _ := f.ForgeSYN(40000, net.ParseIP("10.0.0.2"), 80)
	pkt2, _ := f.ForgeSYN(40001, net.ParseIP("10.0.0.2"), 443)

	// Source ports should differ
	srcPort1 := binary.BigEndian.Uint16(pkt1[20:22])
	srcPort2 := binary.BigEndian.Uint16(pkt2[20:22])
	if srcPort1 == srcPort2 {
		t.Error("different source ports should produce different packets")
	}

	// Destination ports should differ
	dstPort1 := binary.BigEndian.Uint16(pkt1[22:24])
	dstPort2 := binary.BigEndian.Uint16(pkt2[22:24])
	if dstPort1 == dstPort2 {
		t.Error("different destination ports should produce different packets")
	}
}

func TestForgeSYN_DifferentDestIPs(t *testing.T) {
	f := NewForger(net.ParseIP("10.0.0.1"))
	pkt1, _ := f.ForgeSYN(40000, net.ParseIP("10.0.0.2"), 80)
	pkt2, _ := f.ForgeSYN(40000, net.ParseIP("10.0.0.3"), 80)

	dstIP1 := net.IP(pkt1[16:20])
	dstIP2 := net.IP(pkt2[16:20])
	if dstIP1.Equal(dstIP2) {
		t.Error("different dest IPs should produce different packets")
	}
}

func TestForgeSYN_RandomSeqNumber(t *testing.T) {
	f := NewForger(net.ParseIP("10.0.0.1"))
	pkt1, _ := f.ForgeSYN(40000, net.ParseIP("10.0.0.2"), 80)
	pkt2, _ := f.ForgeSYN(40000, net.ParseIP("10.0.0.2"), 80)

	seq1 := binary.BigEndian.Uint32(pkt1[24:28])
	seq2 := binary.BigEndian.Uint32(pkt2[24:28])
	// Very unlikely to be the same (1 in 4B)
	if seq1 == seq2 {
		t.Log("WARNING: two consecutive SEQ numbers are identical (possible but unlikely)")
	}
}

func TestForgeSYN_AckIsZero(t *testing.T) {
	f := NewForger(net.ParseIP("10.0.0.1"))
	pkt, _ := f.ForgeSYN(40000, net.ParseIP("10.0.0.2"), 80)

	tcp := pkt[20:]
	ack := binary.BigEndian.Uint32(tcp[8:12])
	if ack != 0 {
		t.Errorf("ACK number should be 0 for SYN, got %d", ack)
	}
}

// --- Checksum tests ---

func TestCalculateChecksum_KnownValue(t *testing.T) {
	// Simple test: checksum of [0x00, 0x01, 0x00, 0x02] = ~(0x0001 + 0x0002) = ~0x0003 = 0xFFFC
	data := []byte{0x00, 0x01, 0x00, 0x02}
	cs := calculateChecksum(data)
	if cs != 0xFFFC {
		t.Errorf("expected 0xFFFC, got 0x%04X", cs)
	}
}

func TestCalculateChecksum_AllZeros(t *testing.T) {
	data := []byte{0x00, 0x00, 0x00, 0x00}
	cs := calculateChecksum(data)
	if cs != 0xFFFF {
		t.Errorf("expected 0xFFFF for all zeros, got 0x%04X", cs)
	}
}

func TestCalculateChecksum_AllOnes(t *testing.T) {
	data := []byte{0xFF, 0xFF, 0xFF, 0xFF}
	cs := calculateChecksum(data)
	// sum = 0xFFFF + 0xFFFF = 0x1FFFE -> fold -> 0xFFFF -> ~0xFFFF = 0x0000
	if cs != 0x0000 {
		t.Errorf("expected 0x0000 for all ones, got 0x%04X", cs)
	}
}

func TestCalculateChecksum_OddLength(t *testing.T) {
	data := []byte{0x00, 0x01, 0x02}
	// sum = 0x0001 + 0x0200 (odd byte padded) = 0x0201 -> ~0x0201 = 0xFDFE
	cs := calculateChecksum(data)
	if cs != 0xFDFE {
		t.Errorf("expected 0xFDFE for odd-length data, got 0x%04X", cs)
	}
}

func TestCalculateTCPChecksum_NonZero(t *testing.T) {
	srcIP := net.ParseIP("192.168.1.1").To4()
	dstIP := net.ParseIP("192.168.1.2").To4()

	// Minimal TCP header (20 bytes)
	tcpHeader := make([]byte, 20)
	binary.BigEndian.PutUint16(tcpHeader[0:2], 40000) // src port
	binary.BigEndian.PutUint16(tcpHeader[2:4], 80)    // dst port
	tcpHeader[12] = 5 << 4                            // data offset
	tcpHeader[13] = 0x02                               // SYN flag

	cs := calculateTCPChecksum(srcIP, dstIP, tcpHeader)
	if cs == 0 {
		t.Error("TCP checksum should not be zero")
	}
}

func TestCalculateTCPChecksum_VerifyValid(t *testing.T) {
	srcIP := net.ParseIP("10.0.0.1").To4()
	dstIP := net.ParseIP("10.0.0.2").To4()

	tcpHeader := make([]byte, 20)
	binary.BigEndian.PutUint16(tcpHeader[0:2], 50000)
	binary.BigEndian.PutUint16(tcpHeader[2:4], 443)
	tcpHeader[12] = 5 << 4
	tcpHeader[13] = 0x02
	binary.BigEndian.PutUint16(tcpHeader[14:16], 65535) // window

	// Calculate checksum
	cs := calculateTCPChecksum(srcIP, dstIP, tcpHeader)

	// Set checksum in header
	binary.BigEndian.PutUint16(tcpHeader[16:18], cs)

	// Verify: recalculating with checksum set should yield 0 (or 0xFFFF for ones-complement)
	verify := calculateTCPChecksum(srcIP, dstIP, tcpHeader)
	if verify != 0 && verify != 0xFFFF {
		t.Errorf("checksum verification failed: got 0x%04X (expected 0x0000 or 0xFFFF)", verify)
	}
}

// --- buildTCPHeader ---

func TestBuildTCPHeader_SYN(t *testing.T) {
	f := NewForger(net.ParseIP("10.0.0.1"))
	tcp := buildTCPHeader(40000, 80, true, false, false, f.rng)

	if len(tcp) != 20 {
		t.Fatalf("expected 20 bytes, got %d", len(tcp))
	}
	if tcp[13] != 0x02 {
		t.Errorf("flags: expected 0x02 (SYN), got 0x%02x", tcp[13])
	}
}

func TestBuildTCPHeader_SYNACK(t *testing.T) {
	f := NewForger(net.ParseIP("10.0.0.1"))
	tcp := buildTCPHeader(80, 40000, true, true, false, f.rng)

	if tcp[13] != 0x12 {
		t.Errorf("flags: expected 0x12 (SYN+ACK), got 0x%02x", tcp[13])
	}
}

func TestBuildTCPHeader_RST(t *testing.T) {
	f := NewForger(net.ParseIP("10.0.0.1"))
	tcp := buildTCPHeader(80, 40000, false, false, true, f.rng)

	if tcp[13] != 0x04 {
		t.Errorf("flags: expected 0x04 (RST), got 0x%02x", tcp[13])
	}
}

func TestBuildTCPHeader_AllFlags(t *testing.T) {
	f := NewForger(net.ParseIP("10.0.0.1"))
	tcp := buildTCPHeader(80, 40000, true, true, true, f.rng)

	expected := uint8(0x02 | 0x10 | 0x04) // SYN + ACK + RST = 0x16
	if tcp[13] != expected {
		t.Errorf("flags: expected 0x%02x, got 0x%02x", expected, tcp[13])
	}
}

// --- GetInterfaceIP ---

func TestGetInterfaceIP_InvalidInterface(t *testing.T) {
	_, err := GetInterfaceIP("nonexistent-iface-xyz")
	if err == nil {
		t.Error("expected error for invalid interface")
	}
}
