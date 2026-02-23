package helpers

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
)

// TLSInfo contains extracted TLS connection information
type TLSInfo struct {
	Version            string   `json:"version"`
	CipherSuite        string   `json:"cipher_suite"`
	ServerName         string   `json:"server_name,omitempty"`
	CommonName         string   `json:"common_name,omitempty"`
	Organization       []string `json:"organization,omitempty"`
	SANs               []string `json:"sans,omitempty"`
	Issuer             string   `json:"issuer,omitempty"`
	NotBefore          string   `json:"not_before,omitempty"`
	NotAfter           string   `json:"not_after,omitempty"`
	SignatureAlgorithm string   `json:"signature_algorithm,omitempty"`
	PublicKeyAlgorithm string   `json:"public_key_algorithm,omitempty"`
	SelfSigned         bool     `json:"self_signed"`
}

// ExtractTLSInfo extracts comprehensive TLS information from connection
func ExtractTLSInfo(conn *tls.Conn) *TLSInfo {
	state := conn.ConnectionState()
	info := &TLSInfo{
		Version:     tlsVersionString(state.Version),
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
		ServerName:  state.ServerName,
	}

	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		info.CommonName = cert.Subject.CommonName
		info.Organization = cert.Subject.Organization
		info.SANs = cert.DNSNames
		info.Issuer = cert.Issuer.CommonName
		info.NotBefore = cert.NotBefore.Format("2006-01-02")
		info.NotAfter = cert.NotAfter.Format("2006-01-02")
		info.SignatureAlgorithm = cert.SignatureAlgorithm.String()
		info.PublicKeyAlgorithm = cert.PublicKeyAlgorithm.String()
		info.SelfSigned = cert.Subject.CommonName == cert.Issuer.CommonName
	}

	return info
}

// ExtractCertificateInfo extracts information from a certificate
func ExtractCertificateInfo(cert *x509.Certificate) map[string]interface{} {
	return map[string]interface{}{
		"common_name":          cert.Subject.CommonName,
		"organization":         cert.Subject.Organization,
		"organizational_unit":  cert.Subject.OrganizationalUnit,
		"country":              cert.Subject.Country,
		"province":             cert.Subject.Province,
		"locality":             cert.Subject.Locality,
		"issuer":               cert.Issuer.CommonName,
		"issuer_organization":  cert.Issuer.Organization,
		"sans":                 cert.DNSNames,
		"not_before":           cert.NotBefore.Format("2006-01-02 15:04:05"),
		"not_after":            cert.NotAfter.Format("2006-01-02 15:04:05"),
		"signature_algorithm":  cert.SignatureAlgorithm.String(),
		"public_key_algorithm": cert.PublicKeyAlgorithm.String(),
		"serial_number":        cert.SerialNumber.String(),
		"self_signed":          cert.Subject.CommonName == cert.Issuer.CommonName,
	}
}

// tlsVersionString converts TLS version constant to string
func tlsVersionString(version uint16) string {
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

// GetCipherSuiteName returns human-readable cipher suite name
func GetCipherSuiteName(suite uint16) string {
	return tls.CipherSuiteName(suite)
}
