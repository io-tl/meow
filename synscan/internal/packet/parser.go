package packet

import (
	"encoding/binary"
	"net"

	"meow/synscan/pkg/types"
)

// TCPResponse represents a parsed TCP response packet
type TCPResponse struct {
	SrcIP   net.IP
	SrcPort uint16
	DstPort uint16
	Flags   uint8
	SYN     bool
	ACK     bool
	RST     bool
}

// ParseTCPResponse parses a raw IP+TCP packet from the network
func ParseTCPResponse(packet []byte, expectedDstPort uint16) (*TCPResponse, bool) {
	// Verify there are at least 40 bytes (20 IP + 20 TCP minimum)
	if len(packet) < 40 {
		return nil, false
	}

	// Parse the IP header
	ipHeaderLen := int(packet[0]&0x0F) * 4
	if len(packet) < ipHeaderLen+20 {
		return nil, false
	}

	// Extract source IP
	srcIP := net.IPv4(packet[12], packet[13], packet[14], packet[15])

	// Extract the TCP header
	tcpHeader := packet[ipHeaderLen:]

	srcPort := binary.BigEndian.Uint16(tcpHeader[0:2])
	dstPort := binary.BigEndian.Uint16(tcpHeader[2:4])
	flags := tcpHeader[13]

	// Filter on our destination port (scan source port)
	if dstPort != expectedDstPort {
		return nil, false
	}

	// Analyze the TCP flags
	synFlag := (flags & 0x02) != 0
	ackFlag := (flags & 0x10) != 0
	rstFlag := (flags & 0x04) != 0

	return &TCPResponse{
		SrcIP:   srcIP,
		SrcPort: srcPort,
		DstPort: dstPort,
		Flags:   flags,
		SYN:     synFlag,
		ACK:     ackFlag,
		RST:     rstFlag,
	}, true
}

// GetPortState determines the port state from TCP flags
func (r *TCPResponse) GetPortState() types.PortState {
	if r.SYN && r.ACK {
		// Port open (SYN-ACK)
		return types.PortOpen
	} else if r.RST {
		// Port closed (RST)
		return types.PortClosed
	}
	// Other cases (rare)
	return types.PortFiltered
}
