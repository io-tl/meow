package types

import (
	"net"
	"time"
)

// PortState represents the state of a scanned port
type PortState int

const (
	// PortUnknown indicates the port state is unknown
	PortUnknown PortState = iota
	// PortOpen indicates the port is open (SYN-ACK received)
	PortOpen
	// PortClosed indicates the port is closed (RST received)
	PortClosed
	// PortFiltered indicates the port is filtered (no response)
	PortFiltered
)

func (ps PortState) String() string {
	switch ps {
	case PortOpen:
		return "open"
	case PortClosed:
		return "closed"
	case PortFiltered:
		return "filtered"
	default:
		return "unknown"
	}
}

// ScanResult represents the result of a port scan
type ScanResult struct {
	IP        string
	Port      int
	State     PortState
	Timestamp time.Time
	RTT       time.Duration // Round-trip time
}

// OpenPortEvent is published to NATS when an open port is discovered
type OpenPortEvent struct {
	ScanID    string `json:"scan_id"`
	IP        string `json:"ip"`
	Port      int    `json:"port"`
	Timestamp int64  `json:"timestamp"`
}

// ScanRequest is received via NATS when running in daemon mode
type ScanRequest struct {
	RequestID string `json:"request_id"`
	Target    string `json:"target"`
	Ports     string `json:"ports"`
	RateLimit int    `json:"rate_limit,omitempty"`
	Timestamp int64  `json:"timestamp"`
}

// ScannerHeartbeat is published periodically by daemon-mode scanners
type ScannerHeartbeat struct {
	NodeID       string `json:"node_id"`
	Hostname     string `json:"hostname"`
	Status       string `json:"status"` // "idle" or "scanning"
	ScanID       string `json:"scan_id,omitempty"`
	UptimeSec    int64  `json:"uptime_sec"`
	Transport    string `json:"transport,omitempty"`
	PacketsSent  int64  `json:"packets_sent,omitempty"`
	PacketsTotal int64  `json:"packets_total,omitempty"`
	Timestamp    int64  `json:"timestamp"`
}

// ScanConfig represents the configuration for the scanner
type ScanConfig struct {
	// Network
	Interface  string
	SourceIP   net.IP
	SourcePort uint16

	// Targets (use either CIDR or TargetIPs)
	CIDR      string   // Legacy: CIDR notation
	TargetIPs []string // New: explicit list of IPs (nmap-style parsing)
	Ports     []int

	// Performance
	RateLimit   int
	TimeoutMS   int
	SendBatch   int
	RecvBatch   int
	RingSize    int
	IPBatchSize uint32

	// Randomization
	RandomizeIPs        bool
	RandomizePorts      bool
	RandomizeSourcePort bool
	SourcePortMin       uint16
	SourcePortMax       uint16
	TimingJitter        bool
	JitterMaxMS         int

	// Resume
	Seed       int64
	ResumeFrom int

	// NATS
	NATSUrl      string
	NATSToken    string
	NATSUser     string
	NATSPassword string
	ScanID       string
}
