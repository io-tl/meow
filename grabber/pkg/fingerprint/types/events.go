package types

import "time"

// OpenPortEvent représente un événement de port ouvert depuis NATS
type OpenPortEvent struct {
	ScanID    string `json:"scan_id"`
	IP        string `json:"ip"`
	Port      int    `json:"port"`
	Protocol  string `json:"protocol"` // "tcp" ou "udp"
	Timestamp int64  `json:"timestamp"`
}

// FingerprintEvent représente le résultat du fingerprinting publié sur NATS
type FingerprintEvent struct {
	ScanID     string   `json:"scan_id"`
	IP         string   `json:"ip"`
	Port       int      `json:"port"`
	Protocol   string   `json:"protocol"`
	Service    string   `json:"service"`        // ex: "https", "ssh"
	Product    string   `json:"product"`        // ex: "nginx", "OpenSSH"
	Version    string   `json:"version"`        // ex: "1.21.6", "8.2p1"
	Info       string   `json:"info,omitempty"` // ex: "Ubuntu", "protocol 2.0"
	Hostname   string   `json:"hostname,omitempty"`
	OS         string   `json:"os,omitempty"`
	DeviceType string   `json:"device_type,omitempty"`
	CPE        []string `json:"cpe,omitempty"`
	Banner     string   `json:"banner,omitempty"` // Réponse brute (limitée)
	ProbeUsed  string   `json:"probe_used,omitempty"`
	Uncertain  bool     `json:"uncertain,omitempty"`   // Service deviné depuis nmap-services (équivalent au "?" de nmap)
	Failed     bool     `json:"failed,omitempty"`      // Fingerprint attempted but failed (error or no match)
	FailReason string   `json:"fail_reason,omitempty"` // Reason for failure

	// Métadonnées TLS (si applicable)
	TLSVersion      uint16   `json:"tls_version,omitempty"`      // 0x0303 = TLS 1.2
	CipherSuite     uint16   `json:"cipher_suite,omitempty"`     // 0xC02F = ECDHE-RSA-AES128-GCM-SHA256
	ServerName      string   `json:"server_name,omitempty"`      // SNI
	CertificatesPEM []string `json:"certificates_pem,omitempty"` // Certificats en PEM
	JARMFingerprint string   `json:"jarm_fingerprint,omitempty"` // JARM TLS fingerprint

	Timestamp time.Time `json:"timestamp"`
	Duration  int64     `json:"duration_ms"` // Durée du fingerprinting en ms
}
