package modules

import (
	"time"

	"meow/grabber/pkg/enrichment/modules/helpers"
)

// MSSQLModule implements the Microsoft SQL Server enrichment module
type MSSQLModule struct {
	BaseModule
}

// MSSQLResult represents the enriched MSSQL data
type MSSQLResult struct {
	Protocol    string `json:"protocol"`
	Version     string `json:"version,omitempty"`
	ServerName  string `json:"server_name,omitempty"`
	InstanceName string `json:"instance_name,omitempty"`
	Error       string `json:"error,omitempty"`
}

func init() {
	Register(&MSSQLModule{
		BaseModule: NewBaseModule(
			"mssql",
			[]string{"ms-sql", "ms-sql-s"},
			true, // Should enrich
			10*time.Second,
		),
	})
}

func (m *MSSQLModule) Scan(ip string, port int) (interface{}, error) {
	return scanMSSQL(ip, port, m.DefaultTimeout())
}

// scanMSSQL performs MSSQL enrichment
func scanMSSQL(ip string, port int, timeout time.Duration) (*MSSQLResult, error) {
	result := &MSSQLResult{
		Protocol: "mssql",
	}

	// Connect using helper
	conn, err := helpers.DialTCP(ip, port, timeout)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	defer conn.Close()

	// Build TDS pre-login packet
	// TDS packet header (8 bytes) + pre-login data
	prelogin := buildTDSPreloginPacket()

	_, err = conn.Write(prelogin)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	// Read response
	header := make([]byte, 8)
	n, err := conn.Read(header)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	// Ensure we have a complete TDS header
	if n < 4 {
		result.Error = "TDS response header too short"
		return result, nil
	}

	// Parse TDS header
	packetType := header[0]
	if packetType != 0x04 { // Response packet
		result.Error = "Invalid TDS response"
		return result, nil
	}

	// Read packet data using helper
	packetLength := helpers.ReadUint16BE(header, 2)
	if packetLength > 8 && n >= 4 {
		dataLength := int(packetLength) - 8
		if dataLength > 0 && dataLength < 10000 {
			data := make([]byte, dataLength)
			_, err = conn.Read(data)
			if err == nil {
				// Successfully communicated with MSSQL
				result.Version = "detected"
				// Could parse version info from pre-login response
			}
		}
	}

	return result, nil
}

// buildTDSPreloginPacket builds a TDS pre-login packet
func buildTDSPreloginPacket() []byte {
	// Simplified TDS pre-login packet
	packet := make([]byte, 0, 100)

	// TDS header
	header := []byte{
		0x12,       // Packet type: Pre-Login
		0x01,       // Status: EOM
		0x00, 0x2f, // Length (47 bytes)
		0x00, 0x00, // SPID
		0x00,       // Packet ID
		0x00,       // Window
	}
	packet = append(packet, header...)

	// Pre-login options (simplified)
	// Option token: VERSION (0x00)
	packet = append(packet, 0x00)                    // Token
	packet = append(packet, 0x00, 0x08)              // Offset
	packet = append(packet, 0x00, 0x06)              // Length

	// Terminator
	packet = append(packet, 0xff)

	// Version data (6 bytes)
	packet = append(packet, 0x09, 0x00, 0x00, 0x00) // Version
	packet = append(packet, 0x00, 0x00)              // Sub-build

	// Pad to match length
	for len(packet) < 47 {
		packet = append(packet, 0x00)
	}

	// Update actual length
	actualLen := len(packet)
	packet[2] = byte(actualLen >> 8)
	packet[3] = byte(actualLen)

	return packet
}
