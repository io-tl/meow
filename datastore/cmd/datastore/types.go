package main

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"
)

const (
	TopicOpenPort      = "scan.port.open"
	TopicFingerprinted = "scan.port.fingerprinted"
	TopicEnriched      = "scan.port.enriched"
	TopicEnrichRequest = "scan.enrichment.request"
	TopicScanRequest   = "scan.request"
	TopicHeartbeat     = "scan.status.heartbeat"

	StatusPending  = "pending"
	StatusEnriched = "enriched"
	StatusFailed   = "failed"
	StatusSkipped  = "skipped"
)

// FlexibleInt64 can unmarshal from string, int64, or RFC3339 timestamp
type FlexibleInt64 int64

func (f *FlexibleInt64) UnmarshalJSON(data []byte) error {
	// Try int64 first
	var i int64
	if err := json.Unmarshal(data, &i); err == nil {
		*f = FlexibleInt64(i)
		return nil
	}

	// Try string (could be unix timestamp or RFC3339)
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		// Try to parse as int64 string first
		i, err := strconv.ParseInt(s, 10, 64)
		if err == nil {
			*f = FlexibleInt64(i)
			return nil
		}

		// Try to parse as RFC3339 timestamp (RFC3339Nano is a superset of RFC3339)
		t, err := time.Parse(time.RFC3339Nano, s)
		if err == nil {
			*f = FlexibleInt64(t.Unix())
			return nil
		}

		return fmt.Errorf("timestamp string format not recognized: %s", s)
	}

	return fmt.Errorf("timestamp must be int64, string number, or RFC3339 timestamp")
}

type OpenPortEvent struct {
	ScanID    string        `json:"scan_id"`
	IP        string        `json:"ip"`
	Port      int           `json:"port"`
	Timestamp FlexibleInt64 `json:"timestamp"`
}

type FingerprintEvent struct {
	ScanID     string   `json:"scan_id"`
	IP         string   `json:"ip"`
	Port       int      `json:"port"`
	Protocol   string   `json:"protocol"`
	Service    string   `json:"service"`
	Product    string   `json:"product"`
	Version    string   `json:"version"`
	Info       string   `json:"info,omitempty"`
	Hostname   string   `json:"hostname,omitempty"`
	OS         string   `json:"os,omitempty"`
	DeviceType string   `json:"device_type,omitempty"`
	CPE        []string `json:"cpe,omitempty"`
	Banner     string   `json:"banner,omitempty"`
	ProbeUsed  string   `json:"probe_used,omitempty"`
	Failed     bool     `json:"failed,omitempty"`
	FailReason string   `json:"fail_reason,omitempty"`

	TLSVersion      uint16   `json:"tls_version,omitempty"`
	CipherSuite     uint16   `json:"cipher_suite,omitempty"`
	ServerName      string   `json:"server_name,omitempty"`
	CertificatesPEM []string `json:"certificates_pem,omitempty"`
	JARMFingerprint string   `json:"jarm_fingerprint,omitempty"`

	Timestamp FlexibleInt64 `json:"timestamp"`
	Duration  int64         `json:"duration_ms"`
}

type EnrichmentEvent struct {
	IP        string `json:"ip"`
	Port      int    `json:"port"`
	Service   string `json:"service"`
	Domain    string `json:"domain,omitempty"`
	Data      any    `json:"data"`
	Timestamp string `json:"timestamp"`
	Error     string `json:"error,omitempty"`
}

// ScanRequest is published to NATS to request an on-demand scan
type ScanRequest struct {
	RequestID string `json:"request_id"`
	Target    string `json:"target"`
	Ports     string `json:"ports"`
	RateLimit int    `json:"rate_limit,omitempty"`
	Timestamp int64  `json:"timestamp"`
}

// ScannerHeartbeat is received from daemon-mode scanners
type ScannerHeartbeat struct {
	NodeID       string `json:"node_id"`
	Hostname     string `json:"hostname"`
	Status       string `json:"status"`
	ScanID       string `json:"scan_id,omitempty"`
	UptimeSec    int64  `json:"uptime_sec"`
	Transport    string `json:"transport,omitempty"`
	PacketsSent  int64  `json:"packets_sent,omitempty"`
	PacketsTotal int64  `json:"packets_total,omitempty"`
	Timestamp    int64  `json:"timestamp"`
}

// stringOrNil converts []byte to *string, returns nil if empty
func stringOrNil(b []byte) *string {
	if len(b) == 0 {
		return nil
	}
	s := string(b)
	return &s
}
