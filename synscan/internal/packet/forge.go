package packet

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"time"

	"golang.org/x/net/ipv4"
)

// Forger handles TCP SYN packet creation using native Go raw sockets
type Forger struct {
	sourceIP net.IP
	rng      *rand.Rand
}

// NewForger creates a new packet forger
func NewForger(sourceIP net.IP) *Forger {
	return &Forger{
		sourceIP: sourceIP.To4(),
		rng:      rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// ForgeSYN creates a TCP SYN packet with raw sockets (no gopacket dependency)
func (f *Forger) ForgeSYN(srcPort uint16, dstIP net.IP, dstPort uint16) ([]byte, error) {
	return buildIPv4TCPSYNPacket(f.sourceIP, srcPort, dstIP.To4(), dstPort, f.rng), nil
}

// GetSourceIP returns the source IP used by this forger
func (f *Forger) GetSourceIP() net.IP {
	return f.sourceIP
}

// buildIPv4TCPSYNPacket constructs a complete IP + TCP SYN packet
func buildIPv4TCPSYNPacket(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16, rng *rand.Rand) []byte {
	// En-tête IPv4 (20 octets)
	ipHeader := &ipv4.Header{
		Version:  4,
		Len:      20,
		TOS:      0,
		TotalLen: 40, // 20 IP + 20 TCP
		ID:       rng.Intn(65535),
		Flags:    ipv4.DontFragment,
		FragOff:  0,
		TTL:      64,
		Protocol: 6, // TCP
		Src:      srcIP,
		Dst:      dstIP,
	}

	// Serialiser IP
	ipBytes, err := ipHeader.Marshal()
	if err != nil {
		// Fallback to manual IP header construction
		ipBytes = make([]byte, 20)
		ipBytes[0] = 0x45                                                 // Version 4, IHL 5
		ipBytes[1] = 0                                                    // TOS
		binary.BigEndian.PutUint16(ipBytes[2:4], 40)                      // Total length
		binary.BigEndian.PutUint16(ipBytes[4:6], uint16(rng.Intn(65535))) // ID
		binary.BigEndian.PutUint16(ipBytes[6:8], 0x4000)                  // Flags: DF
		ipBytes[8] = 64                                                   // TTL
		ipBytes[9] = 6                                                    // Protocol: TCP
		copy(ipBytes[12:16], srcIP.To4())
		copy(ipBytes[16:20], dstIP.To4())
	}

	// Always calculate IP header checksum — Marshal() leaves it at 0,
	// and NIC TX offloading only applies to kernel-sent packets (not Npcap/AF_PACKET).
	binary.BigEndian.PutUint16(ipBytes[10:12], 0)
	binary.BigEndian.PutUint16(ipBytes[10:12], calculateChecksum(ipBytes))

	// En-tête TCP (20 octets minimum)
	tcpHeader := buildTCPHeader(srcPort, dstPort, true, false, false, rng)

	// Calculer checksum TCP (pseudo-header + TCP)
	tcpChecksum := calculateTCPChecksum(srcIP, dstIP, tcpHeader)
	binary.BigEndian.PutUint16(tcpHeader[16:18], tcpChecksum)

	// Concaténer IP + TCP
	packet := make([]byte, len(ipBytes)+len(tcpHeader))
	copy(packet, ipBytes)
	copy(packet[len(ipBytes):], tcpHeader)

	return packet
}

// buildTCPHeader constructs a TCP header
func buildTCPHeader(srcPort, dstPort uint16, syn, ack, rst bool, rng *rand.Rand) []byte {
	tcp := make([]byte, 20)

	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	binary.BigEndian.PutUint32(tcp[4:8], rng.Uint32()) // SEQ
	binary.BigEndian.PutUint32(tcp[8:12], 0)           // ACK
	tcp[12] = 5 << 4                                   // Data offset = 5 (20 bytes)

	var flags uint8
	if syn {
		flags |= 0x02
	}
	if ack {
		flags |= 0x10
	}
	if rst {
		flags |= 0x04
	}
	tcp[13] = flags

	binary.BigEndian.PutUint16(tcp[14:16], 65535) // Window
	// tcp[16:18] = checksum (rempli après calcul)
	binary.BigEndian.PutUint16(tcp[18:20], 0) // Urgent pointer

	return tcp
}

// calculateTCPChecksum calculates TCP checksum with pseudo-header
func calculateTCPChecksum(srcIP, dstIP net.IP, tcpHeader []byte) uint16 {
	// Pseudo-header pour checksum TCP
	pseudoHeader := make([]byte, 12)
	copy(pseudoHeader[0:4], srcIP.To4())
	copy(pseudoHeader[4:8], dstIP.To4())
	pseudoHeader[8] = 0
	pseudoHeader[9] = 6 // TCP protocol
	binary.BigEndian.PutUint16(pseudoHeader[10:12], uint16(len(tcpHeader)))

	// Concaténer pseudo-header + TCP header
	data := append(pseudoHeader, tcpHeader...)

	return calculateChecksum(data)
}

// calculateChecksum calculates Internet checksum (RFC 1071)
func calculateChecksum(data []byte) uint16 {
	var sum uint32

	// Add 16-bit words
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}

	// Add remaining byte if odd length
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}

	// Fold 32-bit sum to 16 bits
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	return ^uint16(sum)
}

// GetInterfaceIP returns the IPv4 address of a network interface
func GetInterfaceIP(ifaceName string) (net.IP, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("interface not found: %w", err)
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("failed to get interface addresses: %w", err)
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
			return ipnet.IP.To4(), nil
		}
	}

	return nil, fmt.Errorf("no IPv4 address found on interface %s", ifaceName)
}
