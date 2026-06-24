package modules

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strconv"
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
	CurrentDir      string   `json:"current_dir,omitempty"`
	DirectoryList   []string `json:"directory_list,omitempty"`
	ListingStatus   string   `json:"listing_status,omitempty"`
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

	if result.AnonymousLogin {
		result.CurrentDir = ftpCurrentDir(conn, reader)
		if listing, status, passiveOK := ftpAnonymousList(ip, timeout, conn, reader); len(listing) > 0 {
			result.DirectoryList = listing
			result.ListingStatus = status
			result.SupportsPassive = result.SupportsPassive || passiveOK
		} else if status != "" {
			result.ListingStatus = status
			result.SupportsPassive = result.SupportsPassive || passiveOK
		} else if passiveOK {
			result.SupportsPassive = true
		}
	}

	// Send QUIT
	fmt.Fprintf(conn, "QUIT\r\n")

	return result, nil
}

func ftpCurrentDir(conn net.Conn, reader *bufio.Reader) string {
	fmt.Fprintf(conn, "PWD\r\n")
	line, err := reader.ReadString('\n')
	if err != nil {
		return ""
	}
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "257") {
		return ""
	}
	start := strings.IndexByte(line, '"')
	end := strings.LastIndexByte(line, '"')
	if start == -1 || end <= start {
		return ""
	}
	return line[start+1 : end]
}

func ftpAnonymousList(ip string, timeout time.Duration, conn net.Conn, reader *bufio.Reader) ([]string, string, bool) {
	dataHost, dataPort, passiveOK := ftpPassiveEndpoint(ip, conn, reader)
	if !passiveOK {
		return nil, "", false
	}

	dataConn, err := helpers.DialTCP(dataHost, dataPort, timeout)
	if err != nil {
		return nil, "", true
	}
	defer dataConn.Close()

	fmt.Fprintf(conn, "TYPE A\r\n")
	if _, err := reader.ReadString('\n'); err != nil {
		return nil, "", true
	}

	fmt.Fprintf(conn, "LIST\r\n")
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil, "", true
	}
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "125") && !strings.HasPrefix(line, "150") {
		return nil, line, true
	}

	data, err := io.ReadAll(dataConn)
	if err != nil {
		return nil, "", true
	}

	completion, _ := reader.ReadString('\n')
	completion = strings.TrimSpace(completion)

	lines := helpers.SplitLines(string(data))
	if len(lines) > 20 {
		lines = lines[:20]
	}
	return lines, completion, true
}

func ftpPassiveEndpoint(ip string, conn net.Conn, reader *bufio.Reader) (string, int, bool) {
	fmt.Fprintf(conn, "EPSV\r\n")
	epsvResp, err := reader.ReadString('\n')
	if err == nil {
		epsvResp = strings.TrimSpace(epsvResp)
		if strings.HasPrefix(epsvResp, "229") {
			port, err := parseFTPEPSV(epsvResp)
			if err == nil {
				return ip, port, true
			}
		}
	}

	fmt.Fprintf(conn, "PASV\r\n")
	pasvResp, err := reader.ReadString('\n')
	if err != nil {
		return "", 0, false
	}
	pasvResp = strings.TrimSpace(pasvResp)
	if !strings.HasPrefix(pasvResp, "227") {
		return "", 0, false
	}

	dataHost, dataPort, err := parseFTPPASV(pasvResp, ip)
	if err != nil {
		return "", 0, false
	}
	return dataHost, dataPort, true
}

func parseFTPPASV(response, fallbackHost string) (string, int, error) {
	start := strings.IndexByte(response, '(')
	end := strings.IndexByte(response, ')')
	if start == -1 || end == -1 || end <= start+1 {
		return "", 0, fmt.Errorf("invalid PASV response")
	}

	parts := strings.Split(response[start+1:end], ",")
	if len(parts) != 6 {
		return "", 0, fmt.Errorf("invalid PASV address")
	}

	hostParts := make([]string, 4)
	for i := 0; i < 4; i++ {
		hostParts[i] = strings.TrimSpace(parts[i])
	}
	p1, err1 := strconv.Atoi(strings.TrimSpace(parts[4]))
	p2, err2 := strconv.Atoi(strings.TrimSpace(parts[5]))
	if err1 != nil || err2 != nil {
		return "", 0, fmt.Errorf("invalid PASV port")
	}

	host := strings.Join(hostParts, ".")
	if host == "0.0.0.0" || strings.HasPrefix(host, "10.") || strings.HasPrefix(host, "192.168.") || strings.HasPrefix(host, "172.16.") {
		host = fallbackHost
	}

	return host, p1*256 + p2, nil
}

func parseFTPEPSV(response string) (int, error) {
	start := strings.IndexByte(response, '(')
	end := strings.IndexByte(response, ')')
	if start == -1 || end == -1 || end <= start+1 {
		return 0, fmt.Errorf("invalid EPSV response")
	}

	payload := response[start+1 : end]
	if len(payload) < 5 {
		return 0, fmt.Errorf("invalid EPSV payload")
	}

	parts := strings.Split(payload, "|")
	if len(parts) < 5 {
		return 0, fmt.Errorf("invalid EPSV format")
	}

	port, err := strconv.Atoi(strings.TrimSpace(parts[len(parts)-2]))
	if err != nil {
		return 0, fmt.Errorf("invalid EPSV port")
	}
	return port, nil
}
