package modules

import (
	"bufio"
	"fmt"
	"strings"
	"time"

	"meow/grabber/pkg/enrichment/modules/helpers"
)

// SIPModule implements the SIP enrichment module
type SIPModule struct {
	BaseModule
}

// SIPResult represents the enriched SIP data
type SIPResult struct {
	Protocol string            `json:"protocol"`
	Server   string            `json:"server,omitempty"`
	UserAgent string           `json:"user_agent,omitempty"`
	Methods  []string          `json:"methods,omitempty"`
	Headers  map[string]string `json:"headers,omitempty"`
	Error    string            `json:"error,omitempty"`
}

func init() {
	Register(&SIPModule{
		BaseModule: NewBaseModule(
			"sip",
			[]string{},
			true,
			10*time.Second,
		),
	})
}

func (m *SIPModule) Scan(ip string, port int) (interface{}, error) {
	return scanSIP(ip, port, m.DefaultTimeout())
}

func scanSIP(ip string, port int, timeout time.Duration) (*SIPResult, error) {
	result := &SIPResult{
		Protocol: "sip",
		Headers:  make(map[string]string),
	}

	conn, err := helpers.DialUDP(ip, port, timeout)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	defer conn.Close()

	// Send OPTIONS request
	options := fmt.Sprintf(
		"OPTIONS sip:%s:%d SIP/2.0\r\n"+
			"Via: SIP/2.0/UDP %s:5060;branch=z9hG4bK776asdhds\r\n"+
			"Max-Forwards: 70\r\n"+
			"To: <sip:%s:%d>\r\n"+
			"From: Scanner <sip:scanner@scanner.local>;tag=1928301774\r\n"+
			"Call-ID: scanner@scanner\r\n"+
			"CSeq: 1 OPTIONS\r\n"+
			"Contact: <sip:scanner@scanner.local>\r\n"+
			"Accept: application/sdp\r\n"+
			"Content-Length: 0\r\n\r\n",
		ip, port, ip, ip, port)

	_, err = conn.Write([]byte(options))
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	// Read response
	response := make([]byte, 4096)
	n, err := conn.Read(response)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	// Parse SIP response
	scanner := bufio.NewScanner(strings.NewReader(string(response[:n])))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "SIP/2.0") {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			result.Headers[key] = value

			if key == "Server" {
				result.Server = value
			} else if key == "User-Agent" {
				result.UserAgent = value
			} else if key == "Allow" {
				result.Methods = strings.Split(value, ",")
				for i := range result.Methods {
					result.Methods[i] = strings.TrimSpace(result.Methods[i])
				}
			}
		}
	}

	return result, nil
}
