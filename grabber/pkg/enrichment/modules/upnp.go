package modules

import (
	"bufio"
	"strings"
	"time"

	"meow/grabber/pkg/enrichment/modules/helpers"
)

// UPnPModule implements the UPnP enrichment module
type UPnPModule struct {
	BaseModule
}

// UPnPResult represents the enriched UPnP data
type UPnPResult struct {
	Protocol     string            `json:"protocol"`
	Server       string            `json:"server,omitempty"`
	Location     string            `json:"location,omitempty"`
	ST           string            `json:"st,omitempty"` // Search Target
	USN          string            `json:"usn,omitempty"` // Unique Service Name
	Error        string            `json:"error,omitempty"`
}

func init() {
	Register(&UPnPModule{
		BaseModule: NewBaseModule(
			"upnp",
			[]string{"ssdp"},
			true, // Should enrich
			10*time.Second,
		),
	})
}

func (m *UPnPModule) Scan(ip string, port int) (interface{}, error) {
	return scanUPnP(ip, port, m.DefaultTimeout())
}

// scanUPnP performs UPnP/SSDP enrichment
func scanUPnP(ip string, port int, timeout time.Duration) (*UPnPResult, error) {
	result := &UPnPResult{
		Protocol: "upnp",
	}

	// UPnP typically uses UDP
	if port == 1900 {
		return scanUPnPUDP(ip, port, timeout)
	}

	// For TCP ports, try HTTP-based UPnP
	conn, err := helpers.DialTCP(ip, port, timeout)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	defer conn.Close()

	// Send M-SEARCH request
	msearch := "M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 1\r\n" +
		"ST: ssdp:all\r\n" +
		"\r\n"

	_, err = conn.Write([]byte(msearch))
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	// Read response
	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimSpace(line)
		if line == "" {
			break
		}

		// Parse headers
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			key := strings.ToLower(strings.TrimSpace(parts[0]))
			value := strings.TrimSpace(parts[1])

			switch key {
			case "server":
				result.Server = value
			case "location":
				result.Location = value
			case "st":
				result.ST = value
			case "usn":
				result.USN = value
			}
		}
	}

	return result, nil
}

// scanUPnPUDP performs UPnP/SSDP enrichment via UDP
func scanUPnPUDP(ip string, port int, timeout time.Duration) (*UPnPResult, error) {
	result := &UPnPResult{
		Protocol: "upnp",
	}

	conn, err := helpers.DialUDP(ip, port, timeout)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	defer conn.Close()

	// Send M-SEARCH request
	msearch := "M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 1\r\n" +
		"ST: ssdp:all\r\n" +
		"\r\n"

	_, err = conn.Write([]byte(msearch))
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	// Read response
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	// Parse response
	response := string(buffer[:n])
	lines := strings.Split(response, "\r\n")
	for _, line := range lines {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			key := strings.ToLower(strings.TrimSpace(parts[0]))
			value := strings.TrimSpace(parts[1])

			switch key {
			case "server":
				result.Server = value
			case "location":
				result.Location = value
			case "st":
				result.ST = value
			case "usn":
				result.USN = value
			}
		}
	}

	return result, nil
}
