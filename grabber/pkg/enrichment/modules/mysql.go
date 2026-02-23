package modules

import (
	"fmt"
	"io"
	"time"

	"meow/grabber/pkg/enrichment/modules/helpers"
)

// MySQLModule implements the MySQL enrichment module
type MySQLModule struct {
	BaseModule
}

// MySQLResult represents the enriched MySQL data
type MySQLResult struct {
	Protocol       string `json:"protocol"`
	Version        string `json:"version,omitempty"`
	AuthPlugin     string `json:"auth_plugin,omitempty"`
	Capabilities   uint32 `json:"capabilities,omitempty"`
	Error          string `json:"error,omitempty"`
}

func init() {
	Register(&MySQLModule{
		BaseModule: NewBaseModule(
			"mysql",
			[]string{},
			true, // Should enrich
			10*time.Second,
		),
	})
}

func (m *MySQLModule) Scan(ip string, port int) (interface{}, error) {
	return scanMySQL(ip, port, m.DefaultTimeout())
}

// scanMySQL performs MySQL enrichment
func scanMySQL(ip string, port int, timeout time.Duration) (*MySQLResult, error) {
	result := &MySQLResult{
		Protocol: "mysql",
	}

	// Connect using helper
	conn, err := helpers.DialTCP(ip, port, timeout)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	defer conn.Close()

	// Read initial handshake packet
	// MySQL handshake format:
	// 3 bytes: packet length
	// 1 byte: packet number
	// packet data...

	header := make([]byte, 4)
	if _, err = io.ReadFull(conn, header); err != nil {
		result.Error = err.Error()
		return result, err
	}

	packetLength := int(header[0]) | int(header[1])<<8 | int(header[2])<<16
	if packetLength <= 0 || packetLength > 10000 {
		result.Error = "Invalid MySQL packet length"
		return result, nil
	}

	// Read packet data using io.ReadFull to ensure complete read
	packet := make([]byte, packetLength)
	if _, err = io.ReadFull(conn, packet); err != nil {
		result.Error = "Failed to read MySQL handshake packet"
		return result, err
	}

	// Parse handshake packet
	if len(packet) < 10 {
		result.Error = "MySQL handshake packet too short"
		return result, nil
	}

	// Protocol version (1 byte)
	protocolVersion := packet[0]
	if protocolVersion != 10 {
		result.Error = fmt.Sprintf("Unsupported protocol version: %d", protocolVersion)
		return result, nil
	}

	// Server version (null-terminated string) using helper
	pos := 1
	if pos >= len(packet) {
		result.Error = "MySQL packet too short for version"
		return result, nil
	}
	result.Version = helpers.ExtractNullTerminatedString(packet[pos:])

	// Find actual end position of version string (with bounds check)
	versionEnd := pos
	for versionEnd < len(packet) && packet[versionEnd] != 0 {
		versionEnd++
	}

	// Ensure null terminator was found within the packet
	if versionEnd >= len(packet) {
		return result, nil
	}

	// Skip null terminator + connection ID (4 bytes) + auth plugin data part 1 (8 bytes) + filler (1 byte)
	pos = versionEnd + 1 + 4 + 8 + 1
	if pos+2 > len(packet) {
		// Packet too short for capability flags, return what we have
		return result, nil
	}

	// Capability flags (2 bytes lower + 2 bytes upper) using helper
	capLower := helpers.ReadUint16LE(packet, pos)
	pos += 2

	// Skip charset (1), status (2)
	if pos+3 > len(packet) {
		return result, nil
	}
	pos += 1 + 2

	if pos+2 <= len(packet) {
		capUpper := helpers.ReadUint16LE(packet, pos)
		result.Capabilities = uint32(capLower) | (uint32(capUpper) << 16)
		pos += 2
	}

	// Try to extract auth plugin name (at the end of packet)
	// Skip reserved (10 bytes) + auth data part 2 (min 13 bytes)
	if pos+10+13 < len(packet) {
		pos += 10 + 13
		// Auth plugin name is at the end of the packet, null-terminated
		if pos < len(packet) {
			result.AuthPlugin = helpers.ExtractNullTerminatedString(packet[pos:])
		}
	}

	return result, nil
}
