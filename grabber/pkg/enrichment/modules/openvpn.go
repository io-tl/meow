package modules

import (
	"fmt"
	"time"

	"meow/grabber/pkg/enrichment/modules/helpers"
)

// OpenVPNModule implements the OpenVPN enrichment module
type OpenVPNModule struct {
	BaseModule
}

type OpenVPNResult struct {
	Protocol   string `json:"protocol"`
	Response   bool   `json:"response"`
	PacketType string `json:"packet_type,omitempty"`
	SessionID  string `json:"session_id,omitempty"`
	Length     int    `json:"length,omitempty"`
	Error      string `json:"error,omitempty"`
}

func init() {
	Register(&OpenVPNModule{
		BaseModule: NewBaseModule("openvpn", []string{}, false, 10*time.Second),
	})
}

func (m *OpenVPNModule) Scan(ip string, port int) (interface{}, error) {
	result := &OpenVPNResult{Protocol: "openvpn"}
	conn, err := helpers.DialUDP(ip, port, m.DefaultTimeout())
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	defer conn.Close()

	// OpenVPN control packet (reset)
	packet := []byte{0x38, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	conn.Write(packet)

	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	if n >= 14 {
		// Parse OpenVPN packet
		opcode := (response[0] >> 3) & 0x1F

		if opcode == 4 { // P_CONTROL_HARD_RESET_SERVER_V2
			result.Response = true
			result.PacketType = "Control Hard Reset Server V2"

			// Extract session ID (8 bytes starting at offset 1)
			if n >= 9 {
				sessionID := response[1:9]
				result.SessionID = fmt.Sprintf("%02x%02x%02x%02x%02x%02x%02x%02x",
					sessionID[0], sessionID[1], sessionID[2], sessionID[3],
					sessionID[4], sessionID[5], sessionID[6], sessionID[7])
			}

			result.Length = n
		} else if opcode == 5 { // P_CONTROL_V1
			result.Response = true
			result.PacketType = "Control V1"
			result.Length = n

			if n >= 9 {
				sessionID := response[1:9]
				result.SessionID = fmt.Sprintf("%02x%02x%02x%02x%02x%02x%02x%02x",
					sessionID[0], sessionID[1], sessionID[2], sessionID[3],
					sessionID[4], sessionID[5], sessionID[6], sessionID[7])
			}
		} else if (response[0] & 0xf8) == 0x20 {
			result.Response = true
			result.PacketType = fmt.Sprintf("Opcode %d", opcode)
			result.Length = n
		}
	} else if n > 0 && (response[0]&0xf8) == 0x20 {
		result.Response = true
		result.PacketType = "Unknown"
		result.Length = n
	}

	return result, nil
}
