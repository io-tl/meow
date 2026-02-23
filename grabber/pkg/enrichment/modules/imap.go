package modules

import (
	"bufio"
	"io"
	"strings"
	"time"

	"meow/grabber/pkg/enrichment/modules/helpers"
)

// IMAPResult represents the enriched IMAP data
type IMAPResult struct {
	Protocol     string   `json:"protocol"` // imap or imaps
	Banner       string   `json:"banner"`
	Capabilities []string `json:"capabilities,omitempty"`
	TLS          *TLSInfo `json:"tls,omitempty"` // For IMAPS
	Error        string   `json:"error,omitempty"`
}

func init() {
	RegisterPlainAndTLS(
		"imap", []string{},
		"imaps", []string{},
		true, 10*time.Second,
		func(ip string, port int, useTLS bool, domain string, timeout time.Duration) (interface{}, error) {
			return scanIMAP(ip, port, useTLS, domain, timeout)
		},
	)
}

// scanIMAP performs IMAP/IMAPS enrichment
func scanIMAP(ip string, port int, useTLS bool, domain string, timeout time.Duration) (*IMAPResult, error) {
	protocol := "imap"
	if useTLS {
		protocol = "imaps"
	}

	result := &IMAPResult{
		Protocol: protocol,
	}

	var writer io.Writer
	var reader *bufio.Reader
	var err error

	// Connect using helpers
	if useTLS {
		tlsConn, err := helpers.DialTLS(ip, port, domain, timeout)
		if err != nil {
			result.Error = err.Error()
			return result, err
		}
		defer tlsConn.Close()
		reader = bufio.NewReader(tlsConn)
		writer = tlsConn

		// Extract TLS info using helper and convert to shared TLSInfo
		result.TLS = TLSInfoFromHelpers(helpers.ExtractTLSInfo(tlsConn))
	} else {
		conn, err := helpers.DialTCP(ip, port, timeout)
		if err != nil {
			result.Error = err.Error()
			return result, err
		}
		defer conn.Close()
		reader = bufio.NewReader(conn)
		writer = conn
	}

	// Read banner
	banner, err := reader.ReadString('\n')
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	result.Banner = strings.TrimSpace(banner)

	// Try to get capabilities
	if strings.Contains(result.Banner, "* OK") {
		// Send CAPABILITY command
		_, writeErr := writer.Write([]byte("A001 CAPABILITY\r\n"))
		if writeErr == nil {
			// Read capabilities response
			for {
				line, err := reader.ReadString('\n')
				if err != nil {
					break
				}
				line = strings.TrimSpace(line)

				// Parse capability line
				if strings.HasPrefix(line, "* CAPABILITY") {
					caps := strings.Fields(line)[2:] // Skip "* CAPABILITY"
					result.Capabilities = append(result.Capabilities, caps...)
				}

				// End of response
				if strings.HasPrefix(line, "A001 OK") || strings.HasPrefix(line, "A001 NO") || strings.HasPrefix(line, "A001 BAD") {
					break
				}
			}
		}

		// Send LOGOUT
		writer.Write([]byte("A002 LOGOUT\r\n"))
	}

	return result, nil
}
