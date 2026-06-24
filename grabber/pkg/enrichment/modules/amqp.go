package modules

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"meow/grabber/pkg/enrichment/modules/helpers"
)

type AMQPModule struct {
	BaseModule
}

type AMQPResult struct {
	Protocol     string            `json:"protocol"`
	Version      string            `json:"version,omitempty"`
	Product      string            `json:"product,omitempty"`
	Capabilities map[string]string `json:"capabilities,omitempty"`
	ClusterName  string            `json:"cluster_name,omitempty"`
	Copyright    string            `json:"copyright,omitempty"`
	Information  string            `json:"information,omitempty"`
	Platform     string            `json:"platform,omitempty"`
	Mechanisms   string            `json:"mechanisms,omitempty"`
	Locales      string            `json:"locales,omitempty"`
	Error        string            `json:"error,omitempty"`
}

func init() {
	Register(&AMQPModule{
		BaseModule: NewBaseModule("amqp", []string{"rabbitmq"}, true, 10*time.Second),
	})
}

func (m *AMQPModule) Scan(ip string, port int) (interface{}, error) {
	result := &AMQPResult{Protocol: "amqp"}

	// Connect using helper
	conn, err := helpers.DialTCP(ip, port, m.DefaultTimeout())
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	defer conn.Close()

	err = m.handshake(conn, result)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	return result, nil
}

func (m *AMQPModule) handshake(conn net.Conn, result *AMQPResult) error {
	// Send AMQP protocol header (AMQP 0-9-1)
	_, err := conn.Write([]byte("AMQP\x00\x00\x09\x01"))
	if err != nil {
		return fmt.Errorf("failed to send AMQP header: %v", err)
	}

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// Read frame header (7 bytes) + method (4 bytes) = 11 bytes
	frameHeader := make([]byte, 11)
	n, err := conn.Read(frameHeader)
	if err != nil {
		return fmt.Errorf("failed to read frame header: %v", err)
	}

	if n < 11 {
		// Check if server rejected version and sent alternative
		if n >= 8 && string(frameHeader[:4]) == "AMQP" {
			v1, v2, v3, v4 := frameHeader[4], frameHeader[5], frameHeader[6], frameHeader[7]
			return fmt.Errorf("server version mismatch: %d-%d-%d-%d", v1, v2, v3, v4)
		}
		return fmt.Errorf("frame header too short: %d bytes", n)
	}

	// Parse frame header
	frameType := frameHeader[0]
	// channel := binary.BigEndian.Uint16(frameHeader[1:3])
	frameSize := binary.BigEndian.Uint32(frameHeader[3:7])
	method := binary.BigEndian.Uint32(frameHeader[7:11])

	// Verify this is a method frame
	if frameType != 1 {
		return fmt.Errorf("expected method frame (type 1), got type %d", frameType)
	}

	// Verify this is connection.start method (class=10, method=10)
	if method != 0x000A000A {
		return fmt.Errorf("expected connection.start (0x000A000A), got 0x%08X", method)
	}

	// Calculate payload size (frame size - method bytes already read)
	payloadSize := frameSize - 4
	if payloadSize <= 0 || payloadSize > 65536 {
		return fmt.Errorf("invalid payload size: %d", payloadSize)
	}

	// Read the payload
	payload := make([]byte, payloadSize)
	bytesRead := 0
	for bytesRead < int(payloadSize) {
		n, err = conn.Read(payload[bytesRead:])
		if err != nil {
			return fmt.Errorf("failed to read payload: %v", err)
		}
		bytesRead += n
	}

	// Read frame end marker (should be 0xCE)
	frameEnd := make([]byte, 1)
	_, err = conn.Read(frameEnd)
	if err != nil {
		return fmt.Errorf("failed to read frame end: %v", err)
	}

	// Parse the connection.start payload
	return m.parseConnectionStart(payload, result)
}

func (m *AMQPModule) parseConnectionStart(data []byte, result *AMQPResult) error {
	if len(data) < 6 {
		return fmt.Errorf("payload too short: %d bytes", len(data))
	}

	pos := 0

	// Read protocol version (2 bytes)
	versionMajor := data[pos]
	versionMinor := data[pos+1]
	pos += 2

	// Set protocol version based on major.minor
	if versionMajor == 0 && versionMinor == 9 {
		result.Version = "0-9"
	} else if versionMajor == 0 && versionMinor == 8 {
		result.Version = "0-8"
	} else {
		result.Version = fmt.Sprintf("%d-%d", versionMajor, versionMinor)
	}

	// Read server properties table
	if pos+4 > len(data) {
		return fmt.Errorf("insufficient data for table size")
	}

	tableSize := binary.BigEndian.Uint32(data[pos : pos+4])
	pos += 4

	if pos+int(tableSize) > len(data) {
		return fmt.Errorf("table size exceeds payload")
	}

	properties := m.decodeTable(data[pos : pos+int(tableSize)])
	pos += int(tableSize)

	// Extract server properties
	if product, ok := properties["product"]; ok {
		if productStr, ok := product.(string); ok {
			result.Product = productStr
		}
	}
	if version, ok := properties["version"]; ok {
		if versionStr, ok := version.(string); ok {
			// Append server version to protocol version if available
			if result.Product == "RabbitMQ" {
				result.Product = fmt.Sprintf("%s %s", result.Product, versionStr)
			}
		}
	}
	if cluster, ok := properties["cluster_name"]; ok {
		if clusterStr, ok := cluster.(string); ok {
			result.ClusterName = clusterStr
		}
	}
	if copyright, ok := properties["copyright"]; ok {
		if copyrightStr, ok := copyright.(string); ok {
			result.Copyright = copyrightStr
		}
	}
	if info, ok := properties["information"]; ok {
		if infoStr, ok := info.(string); ok {
			result.Information = infoStr
		}
	}
	if platform, ok := properties["platform"]; ok {
		if platformStr, ok := platform.(string); ok {
			result.Platform = platformStr
		}
	}
	if caps, ok := properties["capabilities"]; ok {
		if capsMap, ok := caps.(map[string]interface{}); ok {
			result.Capabilities = make(map[string]string)
			for k, v := range capsMap {
				if boolVal, ok := v.(bool); ok {
					if boolVal {
						result.Capabilities[k] = "YES"
					} else {
						result.Capabilities[k] = "NO"
					}
				}
			}
		}
	}

	// Read mechanisms (long-string)
	if pos+4 <= len(data) {
		mechSize := binary.BigEndian.Uint32(data[pos : pos+4])
		pos += 4
		if pos+int(mechSize) <= len(data) {
			result.Mechanisms = string(data[pos : pos+int(mechSize)])
		}
		pos += int(mechSize)
	}

	// Read locales (long-string)
	if pos+4 <= len(data) {
		localeSize := binary.BigEndian.Uint32(data[pos : pos+4])
		pos += 4
		if pos+int(localeSize) <= len(data) {
			result.Locales = string(data[pos : pos+int(localeSize)])
		}
	}

	return nil
}

func (m *AMQPModule) decodeTable(data []byte) map[string]interface{} {
	properties := make(map[string]interface{})
	pos := 0

	for pos < len(data) {
		// Read key length (1 byte for short string)
		if pos >= len(data) {
			break
		}

		keyLen := int(data[pos])
		pos++

		if pos+keyLen > len(data) {
			break
		}

		key := string(data[pos : pos+keyLen])
		pos += keyLen

		// Read value type
		if pos >= len(data) {
			break
		}

		valueType := data[pos]
		pos++

		switch valueType {
		case 'S': // Long string
			if pos+4 > len(data) {
				return properties
			}
			strLen := binary.BigEndian.Uint32(data[pos : pos+4])
			pos += 4
			if pos+int(strLen) > len(data) {
				return properties
			}
			value := string(data[pos : pos+int(strLen)])
			pos += int(strLen)
			properties[key] = value

		case 's': // Short string
			if pos >= len(data) {
				return properties
			}
			strLen := int(data[pos])
			pos++
			if pos+strLen > len(data) {
				return properties
			}
			value := string(data[pos : pos+strLen])
			pos += strLen
			properties[key] = value

		case 't': // Boolean
			if pos >= len(data) {
				return properties
			}
			value := data[pos] == 1
			pos++
			properties[key] = value

		case 'F': // Field table (nested)
			if pos+4 > len(data) {
				return properties
			}
			tableSize := binary.BigEndian.Uint32(data[pos : pos+4])
			pos += 4
			if pos+int(tableSize) > len(data) {
				return properties
			}
			nestedTable := m.decodeTable(data[pos : pos+int(tableSize)])
			pos += int(tableSize)
			properties[key] = nestedTable

		case 'I': // Signed 32-bit integer
			if pos+4 > len(data) {
				return properties
			}
			value := int32(binary.BigEndian.Uint32(data[pos : pos+4]))
			pos += 4
			properties[key] = value

		case 'i': // Signed 64-bit integer
			if pos+8 > len(data) {
				return properties
			}
			value := int64(binary.BigEndian.Uint64(data[pos : pos+8]))
			pos += 8
			properties[key] = value

		case 'l': // Signed 64-bit integer (long)
			if pos+8 > len(data) {
				return properties
			}
			value := int64(binary.BigEndian.Uint64(data[pos : pos+8]))
			pos += 8
			properties[key] = value

		case 'T': // Timestamp
			if pos+8 > len(data) {
				return properties
			}
			value := binary.BigEndian.Uint64(data[pos : pos+8])
			pos += 8
			properties[key] = value

		case 'V': // Void (no value)
			properties[key] = nil

		default:
			// Unknown type, skip to prevent infinite loop
			return properties
		}
	}

	return properties
}
