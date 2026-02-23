package modules

import (
	"bufio"
	"fmt"
	"strings"
	"time"

	"meow/grabber/pkg/enrichment/modules/helpers"
)

// SMTPModule implements the SMTP enrichment module
type SMTPModule struct {
	BaseModule
}

// SMTPResult represents the enriched SMTP data
type SMTPResult struct {
	Protocol     string   `json:"protocol"`
	Banner       string   `json:"banner"`
	Hostname     string   `json:"hostname,omitempty"`
	Commands     []string `json:"commands,omitempty"`     // Supported commands from EHLO
	SupportsTLS  bool     `json:"supports_tls"`
	SupportsAuth bool     `json:"supports_auth"`
	AuthMethods  []string `json:"auth_methods,omitempty"` // AUTH methods (PLAIN, LOGIN, etc.)
	Error        string   `json:"error,omitempty"`
}

func init() {
	Register(&SMTPModule{
		BaseModule: NewBaseModule(
			"smtp",
			[]string{"smtps", "submission"},
			true, // Should enrich
			10*time.Second,
		),
	})
}

func (m *SMTPModule) Scan(ip string, port int) (interface{}, error) {
	return scanSMTP(ip, port, m.DefaultTimeout())
}

// ScanWithSNI - SMTP can use SNI with STARTTLS, but for basic scan we don't need it
func (m *SMTPModule) ScanWithSNI(ip string, port int, domain string) (interface{}, error) {
	return m.Scan(ip, port)
}

// scanSMTP performs SMTP enrichment
func scanSMTP(ip string, port int, timeout time.Duration) (*SMTPResult, error) {
	result := &SMTPResult{
		Protocol: "smtp",
	}

	// Connect to SMTP server using helper
	conn, err := helpers.DialTCP(ip, port, timeout)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	defer conn.Close()

	// Create a single buffered reader for all communication
	reader := bufio.NewReader(conn)

	// Read welcome banner (220 response) directly with our reader
	banner, err := reader.ReadString('\n')
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	result.Banner = strings.TrimSpace(banner)

	// Extract hostname from banner (usually in format "220 hostname ESMTP ...")
	parts := strings.Fields(result.Banner)
	if len(parts) >= 2 {
		result.Hostname = parts[1]
	}

	// Send EHLO command to get capabilities
	fmt.Fprintf(conn, "EHLO enrichment.scanner\r\n")

	// Read EHLO response (250 responses)
	firstLine := true
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimSpace(line)

		// Parse capabilities
		if strings.HasPrefix(line, "250-") || strings.HasPrefix(line, "250 ") {
			capability := strings.TrimPrefix(line, "250-")
			capability = strings.TrimPrefix(capability, "250 ")

			// Check for STARTTLS
			if strings.HasPrefix(capability, "STARTTLS") {
				result.SupportsTLS = true
			}

			// Check for AUTH
			if strings.HasPrefix(capability, "AUTH ") {
				result.SupportsAuth = true
				authMethods := strings.TrimPrefix(capability, "AUTH ")
				result.AuthMethods = strings.Fields(authMethods)
			}

			// First line is the greeting, not a command
			if !firstLine {
				result.Commands = append(result.Commands, capability)
			}
			firstLine = false
		}

		// End of EHLO response (250 without hyphen)
		if strings.HasPrefix(line, "250 ") {
			break
		}
	}

	// Send QUIT
	fmt.Fprintf(conn, "QUIT\r\n")

	return result, nil
}
