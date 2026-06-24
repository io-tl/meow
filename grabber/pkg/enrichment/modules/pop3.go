package modules

import (
	"bufio"
	"crypto/tls"
	"strings"
	"time"

	"meow/grabber/pkg/enrichment/modules/helpers"
)

// POP3Result represents the enriched POP3 data
type POP3Result struct {
	Protocol     string   `json:"protocol"` // pop3 or pop3s
	Banner       string   `json:"banner"`
	Capabilities []string `json:"capabilities,omitempty"`
	TLS          *TLSInfo `json:"tls,omitempty"` // For POP3S
	Error        string   `json:"error,omitempty"`
}

func init() {
	RegisterPlainAndTLS(
		"pop3", []string{},
		"pop3s", []string{},
		true, 10*time.Second,
		func(ip string, port int, useTLS bool, domain string, timeout time.Duration) (interface{}, error) {
			return scanPOP3(ip, port, useTLS, domain, timeout)
		},
	)
}

// scanPOP3 performs POP3/POP3S enrichment
func scanPOP3(ip string, port int, useTLS bool, domain string, timeout time.Duration) (*POP3Result, error) {
	protocol := "pop3"
	if useTLS {
		protocol = "pop3s"
	}

	result := &POP3Result{
		Protocol: protocol,
	}

	var tlsConn *tls.Conn
	var conn interface {
		Read([]byte) (int, error)
		Write([]byte) (int, error)
		Close() error
	}
	var reader *bufio.Reader
	var err error

	// Connect using helpers
	if useTLS {
		tlsConn, err = helpers.DialTLS(ip, port, domain, timeout)
		if err != nil {
			result.Error = err.Error()
			return result, err
		}
		defer tlsConn.Close()
		conn = tlsConn
		reader = bufio.NewReader(tlsConn)

		// Extract TLS info using helper and convert to shared TLSInfo
		result.TLS = TLSInfoFromHelpers(helpers.ExtractTLSInfo(tlsConn))
	} else {
		tcpConn, err := helpers.DialTCP(ip, port, timeout)
		if err != nil {
			result.Error = err.Error()
			return result, err
		}
		defer tcpConn.Close()
		conn = tcpConn
		reader = bufio.NewReader(tcpConn)
	}

	// Read banner
	banner, err := reader.ReadString('\n')
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	result.Banner = strings.TrimSpace(banner)

	// Try to get capabilities
	if strings.HasPrefix(result.Banner, "+OK") {
		// Send CAPA command
		_, err := conn.Write([]byte("CAPA\r\n"))
		if err == nil {
			// Read capabilities response
			for {
				line, err := reader.ReadString('\n')
				if err != nil {
					break
				}
				line = strings.TrimSpace(line)
				if line == "." {
					break
				}
				if line != "" && !strings.HasPrefix(line, "+OK") {
					result.Capabilities = append(result.Capabilities, line)
				}
			}
		}

		// Send QUIT
		conn.Write([]byte("QUIT\r\n"))
	}

	return result, nil
}
