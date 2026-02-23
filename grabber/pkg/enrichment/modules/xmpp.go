package modules

import (
	"bufio"
	"fmt"
	"strings"
	"time"

	"meow/grabber/pkg/enrichment/modules/helpers"
)

// XMPPModule implements the XMPP/Jabber enrichment module
type XMPPModule struct {
	BaseModule
}

type XMPPResult struct {
	Protocol       string            `json:"protocol"`
	Domain         string            `json:"domain,omitempty"`
	StreamID       string            `json:"stream_id,omitempty"`
	Features       []string          `json:"features,omitempty"`
	Mechanisms     []string          `json:"mechanisms,omitempty"`
	Compression    []string          `json:"compression,omitempty"`
	ServerVersion  string            `json:"server_version,omitempty"`
	ServerSoftware string            `json:"server_software,omitempty"`
	Capabilities   map[string]string `json:"capabilities,omitempty"`
	Error          string            `json:"error,omitempty"`
}

func init() {
	Register(&XMPPModule{
		BaseModule: NewBaseModule("xmpp", []string{"jabber"}, true, 10*time.Second),
	})
}

func (m *XMPPModule) Scan(ip string, port int) (interface{}, error) {
	result := &XMPPResult{
		Protocol:     "xmpp",
		Capabilities: make(map[string]string),
	}

	conn, err := helpers.DialTCP(ip, port, m.DefaultTimeout())
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	defer conn.Close()
	reader := bufio.NewReader(conn)

	// Send XMPP stream initialization
	streamOpen := fmt.Sprintf("<?xml version='1.0'?><stream:stream to='%s' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>", ip)
	_, err = conn.Write([]byte(streamOpen))
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	// Read response
	response := make([]byte, 8192)
	n, err := reader.Read(response)
	if err != nil && n == 0 {
		result.Error = err.Error()
		return result, err
	}

	if n > 0 {
		respStr := string(response[:n])

		// Check for XMPP stream
		if strings.Contains(respStr, "stream:stream") {
			result.Domain = ip

			// Extract stream ID
			if idx := strings.Index(respStr, "id='"); idx >= 0 {
				start := idx + 4
				if end := strings.Index(respStr[start:], "'"); end >= 0 {
					result.StreamID = respStr[start : start+end]
				}
			} else if idx := strings.Index(respStr, `id="`); idx >= 0 {
				start := idx + 4
				if end := strings.Index(respStr[start:], `"`); end >= 0 {
					result.StreamID = respStr[start : start+end]
				}
			}

			// Extract from attribute (server domain)
			if idx := strings.Index(respStr, "from='"); idx >= 0 {
				start := idx + 6
				if end := strings.Index(respStr[start:], "'"); end >= 0 {
					result.Domain = respStr[start : start+end]
				}
			}

			// Parse features
			if strings.Contains(respStr, "starttls") || strings.Contains(respStr, "STARTTLS") {
				result.Features = append(result.Features, "STARTTLS")
			}
			if strings.Contains(respStr, "<bind") {
				result.Features = append(result.Features, "BIND")
			}
			if strings.Contains(respStr, "<session") {
				result.Features = append(result.Features, "SESSION")
			}
			if strings.Contains(respStr, "rosterver") {
				result.Features = append(result.Features, "ROSTER_VERSIONING")
			}
			if strings.Contains(respStr, "sm") || strings.Contains(respStr, "stream-management") {
				result.Features = append(result.Features, "STREAM_MANAGEMENT")
			}

			// Parse SASL mechanisms
			if strings.Contains(respStr, "<mechanisms") {
				mechStart := strings.Index(respStr, "<mechanisms")
				mechEnd := strings.Index(respStr, "</mechanisms>")
				if mechStart >= 0 && mechEnd > mechStart {
					mechSection := respStr[mechStart:mechEnd]

					for _, mech := range []string{"PLAIN", "SCRAM-SHA-1", "SCRAM-SHA-256", "DIGEST-MD5", "ANONYMOUS", "EXTERNAL"} {
						if strings.Contains(mechSection, mech) {
							result.Mechanisms = append(result.Mechanisms, mech)
						}
					}
				}
			}

			// Parse compression methods
			if strings.Contains(respStr, "compression") {
				if strings.Contains(respStr, "zlib") {
					result.Compression = append(result.Compression, "zlib")
				}
			}

			// Try to detect server software from features or version
			if strings.Contains(respStr, "ejabberd") {
				result.ServerSoftware = "ejabberd"
			} else if strings.Contains(respStr, "prosody") {
				result.ServerSoftware = "Prosody"
			} else if strings.Contains(respStr, "openfire") {
				result.ServerSoftware = "Openfire"
			}
		}
	}

	return result, nil
}
