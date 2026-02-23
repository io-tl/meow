package modules

import (
	"bufio"
	"fmt"
	"strings"
	"time"

	"meow/grabber/pkg/enrichment/modules/helpers"
)

// RTSPModule implements the RTSP enrichment module
type RTSPModule struct {
	BaseModule
}

// RTSPResult represents the enriched RTSP data
type RTSPResult struct {
	Protocol string            `json:"protocol"`
	Server   string            `json:"server,omitempty"`
	Methods  []string          `json:"methods,omitempty"`
	Headers  map[string]string `json:"headers,omitempty"`
	Error    string            `json:"error,omitempty"`
}

func init() {
	Register(&RTSPModule{
		BaseModule: NewBaseModule(
			"rtsp",
			[]string{},
			true,
			10*time.Second,
		),
	})
}

func (m *RTSPModule) Scan(ip string, port int) (interface{}, error) {
	return scanRTSP(ip, port, m.DefaultTimeout())
}

func scanRTSP(ip string, port int, timeout time.Duration) (*RTSPResult, error) {
	result := &RTSPResult{
		Protocol: "rtsp",
		Headers:  make(map[string]string),
	}

	conn, err := helpers.DialTCP(ip, port, timeout)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	defer conn.Close()
	reader := bufio.NewReader(conn)

	// Send OPTIONS request
	options := fmt.Sprintf("OPTIONS rtsp://%s:%d/ RTSP/1.0\r\nCSeq: 1\r\n\r\n", ip, port)
	_, err = conn.Write([]byte(options))
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	// Read response
	statusLine, _ := reader.ReadString('\n')
	if strings.HasPrefix(statusLine, "RTSP/1.0") {
		// Read headers
		for {
			line, err := reader.ReadString('\n')
			if err != nil || line == "\r\n" || line == "\n" {
				break
			}

			line = strings.TrimSpace(line)
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				result.Headers[key] = value

				if key == "Server" {
					result.Server = value
				} else if key == "Public" {
					result.Methods = strings.Split(value, ",")
					for i := range result.Methods {
						result.Methods[i] = strings.TrimSpace(result.Methods[i])
					}
				}
			}
		}
	}

	return result, nil
}
