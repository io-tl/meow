package modules

import (
	"bufio"
	"fmt"
	"strings"
	"time"

	"meow/grabber/pkg/enrichment/modules/helpers"
)

// FTPModule implements the FTP enrichment module
type FTPModule struct {
	BaseModule
}

// FTPResult represents the enriched FTP data
type FTPResult struct {
	Protocol        string   `json:"protocol"`
	Banner          string   `json:"banner"`
	WelcomeMessage  string   `json:"welcome_message"`
	Features        []string `json:"features,omitempty"`
	AnonymousLogin  bool     `json:"anonymous_login"`
	SupportsTLS     bool     `json:"supports_tls"`
	SupportsPassive bool     `json:"supports_passive"`
	Error           string   `json:"error,omitempty"`
}

func init() {
	Register(&FTPModule{
		BaseModule: NewBaseModule(
			"ftp",
			[]string{"ftp-data"},
			true, // Should enrich
			10*time.Second,
		),
	})
}

func (m *FTPModule) Scan(ip string, port int) (interface{}, error) {
	return scanFTP(ip, port, m.DefaultTimeout())
}

// ScanWithSNI - FTP doesn't use SNI
func (m *FTPModule) ScanWithSNI(ip string, port int, domain string) (interface{}, error) {
	return m.Scan(ip, port)
}

// scanFTP performs FTP enrichment
func scanFTP(ip string, port int, timeout time.Duration) (*FTPResult, error) {
	result := &FTPResult{
		Protocol: "ftp",
	}

	// Connect to FTP server using helper
	conn, err := helpers.DialTCP(ip, port, timeout)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Read welcome banner (220 response) using helper
	banner, err := helpers.ReadBannerLine(conn)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	result.Banner = banner
	result.WelcomeMessage = banner

	// Try FEAT command to get features
	fmt.Fprintf(conn, "FEAT\r\n")

	// Read FEAT response
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimSpace(line)

		// Check for features
		if strings.Contains(line, "AUTH TLS") || strings.Contains(line, "AUTH SSL") {
			result.SupportsTLS = true
		}
		if strings.Contains(line, "PASV") || strings.Contains(line, "EPSV") {
			result.SupportsPassive = true
		}

		// Store feature
		if line != "" && !strings.HasPrefix(line, "211") {
			result.Features = append(result.Features, line)
		}

		// End of FEAT response (211 End)
		if strings.HasPrefix(line, "211 End") || strings.HasPrefix(line, "211-End") {
			break
		}
	}

	// Try anonymous login
	fmt.Fprintf(conn, "USER anonymous\r\n")
	response, err := reader.ReadString('\n')
	if err == nil {
		response = strings.TrimSpace(response)
		// 331 = password required, 230 = login successful
		if strings.HasPrefix(response, "331") {
			// Try password
			fmt.Fprintf(conn, "PASS anonymous@example.com\r\n")
			passResp, err := reader.ReadString('\n')
			if err == nil {
				passResp = strings.TrimSpace(passResp)
				// 230 = successful login
				if strings.HasPrefix(passResp, "230") {
					result.AnonymousLogin = true
				}
			}
		} else if strings.HasPrefix(response, "230") {
			result.AnonymousLogin = true
		}
	}

	// Send QUIT
	fmt.Fprintf(conn, "QUIT\r\n")

	return result, nil
}
