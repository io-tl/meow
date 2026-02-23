package modules

import (
	"time"

	"meow/grabber/pkg/enrichment/modules/helpers"
)

// OracleModule implements the Oracle database enrichment module
type OracleModule struct {
	BaseModule
}

// OracleResult represents the enriched Oracle data
type OracleResult struct {
	Protocol string `json:"protocol"`
	Version  string `json:"version,omitempty"`
	Banner   string `json:"banner,omitempty"`
	Error    string `json:"error,omitempty"`
}

func init() {
	Register(&OracleModule{
		BaseModule: NewBaseModule(
			"oracle",
			[]string{"oracle-tns"},
			true, // Should enrich
			10*time.Second,
		),
	})
}

func (m *OracleModule) Scan(ip string, port int) (interface{}, error) {
	return scanOracle(ip, port, m.DefaultTimeout())
}

// scanOracle performs Oracle TNS enrichment
func scanOracle(ip string, port int, timeout time.Duration) (*OracleResult, error) {
	result := &OracleResult{
		Protocol: "oracle",
	}

	conn, err := helpers.DialTCP(ip, port, timeout)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	defer conn.Close()

	// Build Oracle TNS Connect packet
	// This is a simplified probe
	tnsConnect := buildTNSConnectPacket()

	_, err = conn.Write(tnsConnect)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	// Read response
	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	if n >= 5 {
		// Check if it's a valid TNS response
		// TNS packet starts with length (2 bytes) + packet checksum (2 bytes) + type (1 byte)
		packetType := response[4]
		if packetType == 0x04 || packetType == 0x02 { // REFUSE or ACCEPT
			result.Version = "detected"
			// Could parse more details from TNS response
		}
	}

	return result, nil
}

// buildTNSConnectPacket builds a simple Oracle TNS connect packet
func buildTNSConnectPacket() []byte {
	// Simplified TNS connect packet
	connectData := "(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=probe)(CID=(PROGRAM=probe))))"

	packet := make([]byte, 0, 200)

	// Packet length (2 bytes) - will update later
	packet = append(packet, 0x00, 0x00)

	// Packet checksum (2 bytes)
	packet = append(packet, 0x00, 0x00)

	// Packet type: CONNECT (0x01)
	packet = append(packet, 0x01)

	// Reserved byte
	packet = append(packet, 0x00)

	// Header checksum (2 bytes)
	packet = append(packet, 0x00, 0x00)

	// Version (2 bytes)
	packet = append(packet, 0x01, 0x39) // Version 313

	// Compatible version (2 bytes)
	packet = append(packet, 0x01, 0x2c) // Version 300

	// Service options (2 bytes)
	packet = append(packet, 0x00, 0x00)

	// Session data unit size (2 bytes)
	packet = append(packet, 0x20, 0x00) // 8192

	// Max transmission data unit size (2 bytes)
	packet = append(packet, 0x7f, 0xff) // 32767

	// NT protocol characteristics (2 bytes)
	packet = append(packet, 0x7f, 0x08)

	// Line turnaround value (2 bytes)
	packet = append(packet, 0x00, 0x00)

	// Value of 1 in hardware (2 bytes)
	packet = append(packet, 0x00, 0x01)

	// Length of connect data (2 bytes)
	connectDataLen := len(connectData)
	packet = append(packet, byte(connectDataLen>>8), byte(connectDataLen))

	// Offset to connect data (2 bytes)
	packet = append(packet, 0x00, 0x3a) // Offset 58

	// Maximum receivable connect data (4 bytes)
	packet = append(packet, 0x00, 0x00, 0x00, 0x00)

	// Connect flags 0 (1 byte)
	packet = append(packet, 0x00)

	// Connect flags 1 (1 byte)
	packet = append(packet, 0x00)

	// Padding to reach offset 58
	for len(packet) < 58 {
		packet = append(packet, 0x00)
	}

	// Add connect data
	packet = append(packet, []byte(connectData)...)

	// Update packet length
	totalLen := len(packet)
	packet[0] = byte(totalLen >> 8)
	packet[1] = byte(totalLen)

	return packet
}
