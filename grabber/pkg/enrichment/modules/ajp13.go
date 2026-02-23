package modules

import (
	"encoding/binary"
	"time"

	"meow/grabber/pkg/enrichment/modules/helpers"
)

// AJP13Module implements the Apache JServ Protocol v1.3 enrichment module
type AJP13Module struct {
	BaseModule
}

// AJP13Result represents the enriched AJP13 data
type AJP13Result struct {
	Protocol string `json:"protocol"`
	Version  string `json:"version,omitempty"`
	Error    string `json:"error,omitempty"`
}

func init() {
	Register(&AJP13Module{
		BaseModule: NewBaseModule(
			"ajp13",
			[]string{"ajp"},
			true, // Should enrich
			10*time.Second,
		),
	})
}

func (m *AJP13Module) Scan(ip string, port int) (interface{}, error) {
	return scanAJP13(ip, port, m.DefaultTimeout())
}

// scanAJP13 performs AJP13 enrichment
func scanAJP13(ip string, port int, timeout time.Duration) (*AJP13Result, error) {
	result := &AJP13Result{
		Protocol: "ajp13",
	}

	conn, err := helpers.DialTCP(ip, port, timeout)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	defer conn.Close()

	// Build AJP13 CPING request
	// AJP13 packet format:
	// - Magic: 0x12 0x34 (2 bytes)
	// - Length: packet length excluding magic and length (2 bytes)
	// - Type: CPING (0x0a) (1 byte)

	cpingRequest := []byte{
		0x12, 0x34, // Magic
		0x00, 0x01, // Length: 1
		0x0a, // Type: CPING
	}

	_, err = conn.Write(cpingRequest)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	// Read response (should be CPONG)
	response := make([]byte, 5)
	n, err := conn.Read(response)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	if n >= 5 {
		// Check magic bytes
		if response[0] == 0x41 && response[1] == 0x42 { // 'AB' magic for response
			// Get packet length
			length := binary.BigEndian.Uint16(response[2:4])
			if length > 0 && response[4] == 0x09 { // CPONG type
				result.Version = "1.3"
			}
		}
	}

	return result, nil
}
