package modules

import (
	"encoding/binary"
	"encoding/json"
	"time"

	"meow/grabber/pkg/enrichment/modules/helpers"
)

// MinecraftModule implements the Minecraft server enrichment module
type MinecraftModule struct {
	BaseModule
}

// MinecraftResult represents the enriched Minecraft data
type MinecraftResult struct {
	Protocol    string                 `json:"protocol"`
	Version     string                 `json:"version,omitempty"`
	Description string                 `json:"description,omitempty"`
	Players     map[string]interface{} `json:"players,omitempty"`
	MOTD        string                 `json:"motd,omitempty"`
	Error       string                 `json:"error,omitempty"`
}

func init() {
	Register(&MinecraftModule{
		BaseModule: NewBaseModule(
			"minecraft",
			[]string{},
			true,
			10*time.Second,
		),
	})
}

func (m *MinecraftModule) Scan(ip string, port int) (interface{}, error) {
	return scanMinecraft(ip, port, m.DefaultTimeout())
}

func scanMinecraft(ip string, port int, timeout time.Duration) (*MinecraftResult, error) {
	result := &MinecraftResult{
		Protocol: "minecraft",
		Players:  make(map[string]interface{}),
	}

	conn, err := helpers.DialTCP(ip, port, timeout)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	defer conn.Close()

	// Send handshake + status request
	handshake := buildMinecraftHandshake(ip, uint16(port))
	statusRequest := []byte{0x01, 0x00} // Packet length 1, packet ID 0 (status request)

	_, err = conn.Write(handshake)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	_, err = conn.Write(statusRequest)
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

	// Parse JSON response (skipping packet framing)
	if n > 5 {
		jsonStart := 3
		for jsonStart < n && response[jsonStart] != '{' {
			jsonStart++
		}
		if jsonStart < n {
			var status map[string]interface{}
			if err := json.Unmarshal(response[jsonStart:n], &status); err == nil {
				if version, ok := status["version"].(map[string]interface{}); ok {
					if name, ok := version["name"].(string); ok {
						result.Version = name
					}
				}
				if desc, ok := status["description"].(map[string]interface{}); ok {
					if text, ok := desc["text"].(string); ok {
						result.Description = text
						result.MOTD = text
					}
				} else if desc, ok := status["description"].(string); ok {
					result.Description = desc
					result.MOTD = desc
				}
				if players, ok := status["players"].(map[string]interface{}); ok {
					result.Players = players
				}
			}
		}
	}

	return result, nil
}

func buildMinecraftHandshake(host string, port uint16) []byte {
	// Truncate hostname to 255 bytes max (Minecraft protocol limit)
	hostBytes := []byte(host)
	if len(hostBytes) > 255 {
		hostBytes = hostBytes[:255]
	}

	buf := []byte{0x00}     // Packet ID: handshake
	buf = append(buf, 0x04) // Protocol version: 4 (1.7.2+)

	// Server address (string) — VarInt length + bytes
	buf = append(buf, byte(len(hostBytes)))
	buf = append(buf, hostBytes...)

	// Server port
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, port)
	buf = append(buf, portBytes...)

	// Next state (1 = status)
	buf = append(buf, 0x01)

	// Add packet length prefix as VarInt
	length := len(buf)
	if length < 128 {
		buf = append([]byte{byte(length)}, buf...)
	} else {
		buf = append([]byte{byte(length&0x7F | 0x80), byte(length >> 7)}, buf...)
	}

	return buf
}
