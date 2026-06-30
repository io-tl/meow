package types

import "time"

// OpenPortEvent represents an open-port event from NATS
type OpenPortEvent struct {
	ScanID    string `json:"scan_id"`
	IP        string `json:"ip"`
	Port      int    `json:"port"`
	Protocol  string `json:"protocol"` // "tcp" or "udp"
	Timestamp int64  `json:"timestamp"`
}

// FingerprintEvent represents the fingerprinting result published to NATS
type FingerprintEvent struct {
	ScanID     string   `json:"scan_id"`
	IP         string   `json:"ip"`
	Port       int      `json:"port"`
	Protocol   string   `json:"protocol"`
	Service    string   `json:"service"`        // e.g. "https", "ssh"
	Product    string   `json:"product"`        // e.g. "nginx", "OpenSSH"
	Version    string   `json:"version"`        // e.g. "1.21.6", "8.2p1"
	Info       string   `json:"info,omitempty"` // e.g. "Ubuntu", "protocol 2.0"
	Hostname   string   `json:"hostname,omitempty"`
	OS         string   `json:"os,omitempty"`
	DeviceType string   `json:"device_type,omitempty"`
	CPE        []string `json:"cpe,omitempty"`
	Banner     string   `json:"banner,omitempty"` // Raw response (limited)
	ProbeUsed  string   `json:"probe_used,omitempty"`
	Uncertain  bool     `json:"uncertain,omitempty"`   // Service guessed from nmap-services (equivalent to nmap's "?")
	Failed     bool     `json:"failed,omitempty"`      // Fingerprint attempted but failed (error or no match)
	FailReason string   `json:"fail_reason,omitempty"` // Reason for failure

	// TLS metadata (if applicable)
	TLSVersion      uint16   `json:"tls_version,omitempty"`      // 0x0303 = TLS 1.2
	CipherSuite     uint16   `json:"cipher_suite,omitempty"`     // 0xC02F = ECDHE-RSA-AES128-GCM-SHA256
	ServerName      string   `json:"server_name,omitempty"`      // SNI
	CertificatesPEM []string `json:"certificates_pem,omitempty"` // Certificates in PEM
	JARMFingerprint string   `json:"jarm_fingerprint,omitempty"` // JARM TLS fingerprint

	Timestamp time.Time `json:"timestamp"`
	Duration  int64     `json:"duration_ms"` // Fingerprinting duration in ms
}
