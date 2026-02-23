package modules

import (
	"encoding/binary"
	"time"

	"meow/grabber/pkg/enrichment/modules/helpers"
)

// PPTPModule implements the PPTP enrichment module
type PPTPModule struct {
	BaseModule
}

type PPTPResult struct {
	Protocol string `json:"protocol"`
	Version  string `json:"version,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	Vendor   string `json:"vendor,omitempty"`
	Error    string `json:"error,omitempty"`
}

func init() {
	Register(&PPTPModule{
		BaseModule: NewBaseModule("pptp", []string{}, false, 10*time.Second),
	})
}

func (m *PPTPModule) Scan(ip string, port int) (interface{}, error) {
	result := &PPTPResult{Protocol: "pptp"}
	conn, err := helpers.DialTCP(ip, port, m.DefaultTimeout())
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	defer conn.Close()

	// PPTP Start-Control-Connection-Request
	request := make([]byte, 156)
	binary.BigEndian.PutUint16(request[0:2], 156)  // Length
	binary.BigEndian.PutUint16(request[2:4], 1)    // Message Type: Control
	binary.BigEndian.PutUint32(request[4:8], 0x1a2b3c4d) // Magic Cookie
	binary.BigEndian.PutUint16(request[8:10], 1)   // Control Message Type: Start-Control-Connection-Request
	binary.BigEndian.PutUint16(request[12:14], 0x0100) // Protocol Version 1.0

	conn.Write(request)

	response := make([]byte, 156)
	n, err := conn.Read(response)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	if n >= 84 {
		msgType := binary.BigEndian.Uint16(response[8:10])
		if msgType == 2 { // Start-Control-Connection-Reply
			result.Version = "1.0"

			// Extract hostname from response[20:84] (64 bytes, null-terminated string)
			hostnameBytes := response[20:84]
			hostname := ""
			for i, b := range hostnameBytes {
				if b == 0 {
					hostname = string(hostnameBytes[:i])
					break
				}
			}
			if hostname != "" {
				result.Hostname = hostname
			}

			// Extract vendor from response[84:148] if available
			if n >= 148 {
				vendorBytes := response[84:148]
				vendor := ""
				for i, b := range vendorBytes {
					if b == 0 {
						vendor = string(vendorBytes[:i])
						break
					}
				}
				if vendor != "" {
					result.Vendor = vendor
				}
			}
		}
	}

	return result, nil
}
