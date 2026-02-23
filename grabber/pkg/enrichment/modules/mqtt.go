package modules

import (
	"fmt"
	"time"

	"meow/grabber/pkg/enrichment/modules/helpers"
)

// MQTTModule implements the MQTT enrichment module
type MQTTModule struct {
	BaseModule
}

// MQTTResult represents the enriched MQTT data
type MQTTResult struct {
	Protocol       string `json:"protocol"`
	Version        string `json:"version,omitempty"`
	ProtocolLevel  int    `json:"protocol_level,omitempty"`
	Connected      bool   `json:"connected"`
	ReturnCode     int    `json:"return_code,omitempty"`
	ReturnCodeDesc string `json:"return_code_description,omitempty"`
	SessionPresent bool   `json:"session_present,omitempty"`
	Error          string `json:"error,omitempty"`
}

func init() {
	Register(&MQTTModule{
		BaseModule: NewBaseModule(
			"mqtt",
			[]string{"mqtts"},
			true,
			10*time.Second,
		),
	})
}

func (m *MQTTModule) Scan(ip string, port int) (interface{}, error) {
	return scanMQTT(ip, port, m.DefaultTimeout())
}

func scanMQTT(ip string, port int, timeout time.Duration) (*MQTTResult, error) {
	result := &MQTTResult{
		Protocol: "mqtt",
	}

	conn, err := helpers.DialTCP(ip, port, timeout)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	defer conn.Close()

	// MQTT CONNECT packet (simplified)
	connectPacket := []byte{
		0x10, 0x10, // Fixed header: CONNECT, remaining length 16
		0x00, 0x04, 'M', 'Q', 'T', 'T', // Protocol name
		0x04,       // Protocol level (3.1.1)
		0x02,       // Connect flags (clean session)
		0x00, 0x3c, // Keep alive (60 seconds)
		0x00, 0x04, 't', 'e', 's', 't', // Client ID "test"
	}

	_, err = conn.Write(connectPacket)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	// Read CONNACK
	response := make([]byte, 4)
	n, err := conn.Read(response)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	if n >= 4 && (response[0]&0xF0) == 0x20 {
		// CONNACK packet
		result.ProtocolLevel = 4
		result.Version = "3.1.1"

		// Parse CONNACK flags
		if n >= 4 {
			sessionPresent := response[2] & 0x01
			returnCode := response[3]

			result.SessionPresent = sessionPresent == 1
			result.ReturnCode = int(returnCode)

			if returnCode == 0 {
				result.Connected = true
				result.ReturnCodeDesc = "Connection Accepted"
			} else {
				result.ReturnCodeDesc = getMQTTReturnCodeDesc(returnCode)
			}
		}
	}

	return result, nil
}

// getMQTTReturnCodeDesc returns description for MQTT return code
func getMQTTReturnCodeDesc(code byte) string {
	switch code {
	case 0:
		return "Connection Accepted"
	case 1:
		return "Unacceptable protocol version"
	case 2:
		return "Identifier rejected"
	case 3:
		return "Server unavailable"
	case 4:
		return "Bad user name or password"
	case 5:
		return "Not authorized"
	default:
		return fmt.Sprintf("Unknown code %d", code)
	}
}
