package transport

import (
	"context"
	"net"
	"time"
)

// TransportMethod represents the type of transport
type TransportMethod int

const (
	// TransportAFPacket uses AF_PACKET with mmap (PACKET_TX_RING/RX_RING)
	// Fastest method, requires CAP_NET_RAW or root, kernel 2.6.27+
	TransportAFPacket TransportMethod = iota

	// TransportRawSocket uses raw sockets with sendmmsg/recvmmsg
	// Fast method, requires CAP_NET_RAW or root, works on older 2.6.x kernels
	TransportRawSocket

	// TransportConnect uses standard TCP connect()
	// Slowest method, works without privileges, performs full 3-way handshake
	TransportConnect

	// TransportNpcap uses Npcap on Windows for raw packet injection
	// Requires Npcap installed + Administrator privileges
	TransportNpcap
)

func (t TransportMethod) String() string {
	switch t {
	case TransportAFPacket:
		return "AF_PACKET+mmap"
	case TransportRawSocket:
		return "Raw Socket"
	case TransportConnect:
		return "Connect"
	case TransportNpcap:
		return "Npcap"
	default:
		return "Unknown"
	}
}

// Packet represents a packet to send or a received packet
type Packet struct {
	Data    []byte
	DstIP   net.IP
	DstPort uint16
	SrcPort uint16
	Length  int
}

// TransportConfig holds transport configuration
type TransportConfig struct {
	SourceIP      net.IP
	Interface     string
	SendBatchSize int
	RecvBatchSize int
	RingSize      int // For AF_PACKET mmap
	TimeoutMS     int
}

// ReceivedPacket represents a received packet with metadata
type ReceivedPacket struct {
	Data      []byte
	SrcIP     net.IP
	SrcPort   uint16
	DstPort   uint16
	Flags     uint8
	Timestamp time.Time
}

// Transport is the interface that all transport methods must implement
type Transport interface {
	// Method returns the transport method type
	Method() TransportMethod

	// Send sends a batch of packets
	// Returns number of packets sent and error
	Send(packets []*Packet) (int, error)

	// Receive receives a batch of packets
	// Returns received packets and error
	Receive(ctx context.Context) ([]*ReceivedPacket, error)

	// Close closes the transport and releases resources
	Close() error

	// GetCapabilities returns what this transport can do
	GetCapabilities() Capabilities
}

// Capabilities describes what a transport method can do
type Capabilities struct {
	// SupportsSYNScan indicates if true SYN scanning is supported
	SupportsSYNScan bool

	// SupportsCustomSourcePort indicates if custom source ports can be used
	SupportsCustomSourcePort bool

	// SupportsRawPackets indicates if raw packet crafting is supported
	SupportsRawPackets bool

	// RequiresRoot indicates if root/CAP_NET_RAW is required
	RequiresRoot bool

	// MaxPacketsPerSecond is an estimate of maximum PPS this method can achieve
	MaxPacketsPerSecond int
}
