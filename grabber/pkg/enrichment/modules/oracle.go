package modules

import (
	"encoding/binary"
	"regexp"
	"strings"
	"time"

	"meow/grabber/pkg/enrichment/modules/helpers"
)

// OracleModule implements the Oracle database enrichment module
type OracleModule struct {
	BaseModule
}

// OracleResult represents the enriched Oracle data
type OracleResult struct {
	Protocol      string   `json:"protocol"`
	Version       string   `json:"version,omitempty"`
	Banner        string   `json:"banner,omitempty"`
	PacketType    string   `json:"packet_type,omitempty"`
	ServiceName   string   `json:"service_name,omitempty"`
	InstanceName  string   `json:"instance_name,omitempty"`
	Host          string   `json:"host,omitempty"`
	Port          string   `json:"port,omitempty"`
	Program       string   `json:"program,omitempty"`
	Errors        []string `json:"errors,omitempty"`
	RawDescriptor string   `json:"raw_descriptor,omitempty"`
	Error         string   `json:"error,omitempty"`
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

	header := make([]byte, 8)
	n, err := conn.Read(header)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	if n < 8 {
		return result, nil
	}

	packetLength := int(binary.BigEndian.Uint16(header[0:2]))
	packetType := header[4]
	result.PacketType = oracleTNSTypeName(packetType)

	response := append([]byte{}, header[:n]...)
	if packetLength > n && packetLength <= 32*1024 {
		rest := make([]byte, packetLength-n)
		readN, _ := conn.Read(rest)
		response = append(response, rest[:readN]...)
	}

	if packetType == 0x04 || packetType == 0x02 || packetType == 0x0b {
		result.Version = "detected"
	}

	payload := string(response)
	result.RawDescriptor = oracleExtractDescriptor(payload)
	if result.RawDescriptor != "" {
		result.Banner = result.RawDescriptor
		result.Version = firstNonEmpty(oracleExtractVersion(result.RawDescriptor), result.Version)
		result.ServiceName = oracleExtractKey(result.RawDescriptor, "SERVICE_NAME")
		result.InstanceName = oracleExtractKey(result.RawDescriptor, "INSTANCE_NAME")
		result.Host = oracleExtractKey(result.RawDescriptor, "HOST")
		result.Port = oracleExtractKey(result.RawDescriptor, "PORT")
		result.Program = oracleExtractKey(result.RawDescriptor, "PROGRAM")
	}

	result.Errors = oracleExtractErrors(payload)
	if len(result.Errors) > 0 && result.Error == "" {
		result.Error = result.Errors[0]
	}
	if result.Banner == "" && len(result.Errors) > 0 {
		result.Banner = strings.Join(result.Errors, "; ")
	}

	return result, nil
}

func oracleTNSTypeName(packetType byte) string {
	switch packetType {
	case 0x01:
		return "CONNECT"
	case 0x02:
		return "ACCEPT"
	case 0x04:
		return "REFUSE"
	case 0x05:
		return "REDIRECT"
	case 0x0b:
		return "RESEND"
	default:
		return ""
	}
}

func oracleExtractDescriptor(payload string) string {
	start := strings.Index(payload, "(DESCRIPTION=")
	if start == -1 {
		return ""
	}

	depth := 0
	for i := start; i < len(payload); i++ {
		switch payload[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return payload[start : i+1]
			}
		}
	}
	return strings.TrimSpace(payload[start:])
}

func oracleExtractKey(payload, key string) string {
	re := regexp.MustCompile(`\(` + regexp.QuoteMeta(key) + `=([^)]+)\)`)
	match := re.FindStringSubmatch(payload)
	if len(match) < 2 {
		return ""
	}
	return strings.TrimSpace(match[1])
}

func oracleExtractVersion(payload string) string {
	re := regexp.MustCompile(`(?i)VERSION=([0-9][0-9A-Za-z\.\-_]+)`)
	match := re.FindStringSubmatch(payload)
	if len(match) < 2 {
		return ""
	}
	return strings.TrimSpace(match[1])
}

func oracleExtractErrors(payload string) []string {
	re := regexp.MustCompile(`(?:ORA|TNS)-\d{4,5}:[^\r\n\000]+`)
	matches := re.FindAllString(payload, -1)
	if len(matches) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(matches))
	var result []string
	for _, match := range matches {
		match = strings.TrimSpace(match)
		if _, ok := seen[match]; ok {
			continue
		}
		seen[match] = struct{}{}
		result = append(result, match)
	}
	return result
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
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
