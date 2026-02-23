package modules

import (
	"crypto/tls"
	"fmt"
	"time"

	"meow/grabber/pkg/enrichment/modules/helpers"
)

// TLSInfo represents TLS/SSL certificate information
type TLSInfo struct {
	Version          string     `json:"version"`
	CipherSuite      string     `json:"cipher_suite"`
	ServerName       string     `json:"server_name,omitempty"`
	PeerCertificates []CertInfo `json:"peer_certificates,omitempty"`
	VerifiedChains   bool       `json:"verified_chains"`
}

// CertInfo represents X.509 certificate information
type CertInfo struct {
	Subject            string   `json:"subject"`
	Issuer             string   `json:"issuer"`
	CommonName         string   `json:"common_name"`
	DNSNames           []string `json:"dns_names,omitempty"`
	NotBefore          string   `json:"not_before"`
	NotAfter           string   `json:"not_after"`
	SignatureAlgorithm string   `json:"signature_algorithm"`
	PublicKeyAlgorithm string   `json:"public_key_algorithm"`
}

// TLSInfoFromHelpers converts helpers.TLSInfo to the shared modules.TLSInfo struct.
// Used by POP3, IMAP, LDAP and other modules that extract TLS via helpers.ExtractTLSInfo().
func TLSInfoFromHelpers(h *helpers.TLSInfo) *TLSInfo {
	info := &TLSInfo{
		Version:     h.Version,
		CipherSuite: h.CipherSuite,
		ServerName:  h.ServerName,
	}
	if h.CommonName != "" {
		info.PeerCertificates = []CertInfo{
			{
				CommonName:         h.CommonName,
				DNSNames:           h.SANs,
				Issuer:             h.Issuer,
				NotBefore:          h.NotBefore,
				NotAfter:           h.NotAfter,
				SignatureAlgorithm: h.SignatureAlgorithm,
				PublicKeyAlgorithm: h.PublicKeyAlgorithm,
			},
		}
	}
	return info
}

// TLSInfoFromConnectionState converts a tls.ConnectionState to the shared TLSInfo struct.
// Used by RDP, AFP and other modules that perform TLS handshakes directly.
func TLSInfoFromConnectionState(state *tls.ConnectionState) *TLSInfo {
	info := &TLSInfo{
		Version:        getTLSVersionString(state.Version),
		CipherSuite:    tls.CipherSuiteName(state.CipherSuite),
		ServerName:     state.ServerName,
		VerifiedChains: len(state.VerifiedChains) > 0,
	}

	for _, cert := range state.PeerCertificates {
		certInfo := CertInfo{
			Subject:            cert.Subject.String(),
			Issuer:             cert.Issuer.String(),
			CommonName:         cert.Subject.CommonName,
			DNSNames:           cert.DNSNames,
			NotBefore:          cert.NotBefore.Format(time.RFC3339),
			NotAfter:           cert.NotAfter.Format(time.RFC3339),
			SignatureAlgorithm: cert.SignatureAlgorithm.String(),
			PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
		}
		info.PeerCertificates = append(info.PeerCertificates, certInfo)
	}

	return info
}

// getTLSVersionString converts TLS version constant to string
func getTLSVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionSSL30:
		return "SSL 3.0"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", version)
	}
}
