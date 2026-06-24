package modules

import (
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
	"meow/grabber/pkg/enrichment/modules/helpers"
)

// SSHModule implements the SSH enrichment module (without zgrab)
type SSHModule struct {
	BaseModule
}

// SSHResult represents the enriched SSH data
type SSHResult struct {
	Protocol       string    `json:"protocol"`
	Banner         string    `json:"banner"`
	ServerVersion  string    `json:"server_version"`
	HostKeyAlgos   []string  `json:"host_key_algorithms,omitempty"`
	KexAlgos       []string  `json:"kex_algorithms,omitempty"`
	Ciphers        []string  `json:"ciphers,omitempty"`
	MACs           []string  `json:"macs,omitempty"`
	Compressions   []string  `json:"compressions,omitempty"`
	ServerHostKeys []HostKey `json:"server_host_keys,omitempty"`
	Error          string    `json:"error,omitempty"`
}

// HostKey represents an SSH host key
type HostKey struct {
	Type        string `json:"type"`
	Fingerprint string `json:"fingerprint"` // SHA256 fingerprint
}

func init() {
	Register(&SSHModule{
		BaseModule: NewBaseModule(
			"ssh",
			[]string{},
			true, // Should enrich
			10*time.Second,
		),
	})
}

func (m *SSHModule) Scan(ip string, port int) (interface{}, error) {
	return scanSSH(ip, port, m.DefaultTimeout())
}

// ScanWithSNI - SSH doesn't use SNI, so just use regular scan
func (m *SSHModule) ScanWithSNI(ip string, port int, domain string) (interface{}, error) {
	return m.Scan(ip, port)
}

// scanSSH performs SSH enrichment using a single TCP connection
func scanSSH(ip string, port int, timeout time.Duration) (*SSHResult, error) {
	result := &SSHResult{
		Protocol: "ssh",
	}

	target := fmt.Sprintf("%s:%d", ip, port)

	// Single TCP connection for the entire probe
	tcpConn, err := helpers.DialTCP(ip, port, timeout)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	defer tcpConn.Close()

	// Config that collects server info during handshake
	config := &ssh.ClientConfig{
		User: "probe",
		Auth: []ssh.AuthMethod{
			ssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) ([]string, error) {
				return make([]string, len(questions)), nil
			}),
		},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			result.ServerHostKeys = append(result.ServerHostKeys, HostKey{
				Type:        key.Type(),
				Fingerprint: ssh.FingerprintSHA256(key),
			})
			return nil
		},
		Timeout:       timeout,
		ClientVersion: "SSH-2.0-EnrichmentScanner",
	}

	// Perform SSH handshake on the existing TCP connection
	sshConn, chans, reqs, err := ssh.NewClientConn(tcpConn, target, config)
	if err != nil {
		// Auth failure is expected — we still collect server info from handshake
		if sshConn != nil {
			result.Banner = string(sshConn.ServerVersion())
			result.ServerVersion = result.Banner
			sshConn.Close()
		}
		// Only report non-auth errors
		if _, ok := err.(*ssh.ServerAuthError); !ok {
			result.Error = err.Error()
		}
		return result, nil
	}
	defer sshConn.Close()

	// Successful handshake (unexpected without creds, but handle it)
	_ = ssh.NewClient(sshConn, chans, reqs)
	result.Banner = string(sshConn.ServerVersion())
	result.ServerVersion = result.Banner

	return result, nil
}
