package modules

import (
	"fmt"
	"time"

	"meow/grabber/pkg/enrichment/modules/helpers"
)

// SyslogModule implements the Syslog enrichment module
type SyslogModule struct {
	BaseModule
}

type SyslogResult struct {
	Protocol     string `json:"protocol"`
	Transport    string `json:"transport,omitempty"`
	UDPAccepted  bool   `json:"udp_accepted"`
	TCPConnected bool   `json:"tcp_connected"`
	TLSSupported bool   `json:"tls_supported"`
	Error        string `json:"error,omitempty"`
}

func init() {
	Register(&SyslogModule{
		BaseModule: NewBaseModule("syslog", []string{}, false, 5*time.Second),
	})
}

func (m *SyslogModule) Scan(ip string, port int) (interface{}, error) {
	result := &SyslogResult{Protocol: "syslog"}

	// Try UDP first (traditional syslog)
	connUDP, err := helpers.DialUDP(ip, port, m.DefaultTimeout())
	if err == nil {
		defer connUDP.Close()

		// Send test syslog message (RFC 5424 format)
		msg := "<14>1 2025-01-01T00:00:00Z scanner test - - - Probe"
		_, err = connUDP.Write([]byte(msg))
		if err == nil {
			result.UDPAccepted = true
			result.Transport = "UDP"
		}
	}

	// Try TCP (RFC 6587)
	connTCP, err := helpers.DialTCP(ip, port, m.DefaultTimeout())
	if err == nil {
		defer connTCP.Close()
		result.TCPConnected = true
		if result.Transport == "" {
			result.Transport = "TCP"
		} else {
			result.Transport = "UDP/TCP"
		}

		// Try to send a message with frame length prefix
		msg := "<14>1 2025-01-01T00:00:00Z scanner test - - - Probe\n"
		frameMsg := fmt.Sprintf("%d %s", len(msg), msg)
		_, err = connTCP.Write([]byte(frameMsg))
		if err != nil {
			result.Error = err.Error()
			return result, err
		}
	}

	// Try TLS on port 6514
	if port == 6514 {
		connTLS, err := helpers.DialTCP(ip, port, m.DefaultTimeout())
		if err == nil {
			connTLS.Close()
			result.TLSSupported = true
			result.Transport = "TLS"
		}
	}

	if !result.UDPAccepted && !result.TCPConnected {
		result.Error = "No response on UDP or TCP"
	}

	return result, nil
}
