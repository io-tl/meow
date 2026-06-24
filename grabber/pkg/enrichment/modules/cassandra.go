package modules

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"meow/grabber/pkg/enrichment/modules/helpers"
)

// CassandraModule implements the Cassandra enrichment module
type CassandraModule struct {
	BaseModule
}

type CassandraResult struct {
	Protocol         string            `json:"protocol"`
	ProtocolVersion  string            `json:"protocol_version,omitempty"`
	CQLVersions      []string          `json:"cql_versions,omitempty"`
	Compression      []string          `json:"compression,omitempty"`
	SupportedOptions map[string]string `json:"supported_options,omitempty"`
	ClusterName      string            `json:"cluster_name,omitempty"`
	DataCenter       string            `json:"datacenter,omitempty"`
	CassandraVersion string            `json:"cassandra_version,omitempty"`
	Error            string            `json:"error,omitempty"`
}

func init() {
	Register(&CassandraModule{
		BaseModule: NewBaseModule("cassandra", []string{}, true, 10*time.Second),
	})
}

func (m *CassandraModule) Scan(ip string, port int) (interface{}, error) {
	result := &CassandraResult{
		Protocol:         "cassandra",
		SupportedOptions: make(map[string]string),
	}

	conn, err := helpers.DialTCP(ip, port, m.DefaultTimeout())
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	defer conn.Close()

	// Try CQL protocol v4 first, then v5
	for _, version := range []byte{0x04, 0x05} {
		// CQL native protocol OPTIONS frame
		frame := []byte{
			version,    // Version
			0x00,       // Flags
			0x00, 0x01, // Stream ID
			0x05,                   // Opcode: OPTIONS
			0x00, 0x00, 0x00, 0x00, // Length: 0
		}

		if _, err := conn.Write(frame); err != nil {
			if version == 0x05 {
				result.Error = err.Error()
			}
			continue
		}

		response := make([]byte, 2048)
		n, err := conn.Read(response)
		if err != nil {
			if version == 0x05 {
				result.Error = err.Error()
			}
			continue
		}

		if n < 9 {
			continue
		}

		// Parse response header
		responseVersion := response[0]
		if responseVersion != 0x84 && responseVersion != 0x85 {
			continue
		}

		result.ProtocolVersion = fmt.Sprintf("v%d", responseVersion&0x0F)

		opcode := response[4]
		bodyLength := binary.BigEndian.Uint32(response[5:9])

		// Cap body length to prevent excessive allocation
		if bodyLength > 65536 {
			continue
		}

		// SUPPORTED response (opcode 0x06)
		if opcode == 0x06 && bodyLength > 0 && n >= int(9+bodyLength) {
			parseMultimap(response[9:9+bodyLength], result)
		}

		// Try to get system information via a query
		if result.ProtocolVersion != "" {
			getSystemInfo(conn, version, result)
		}

		break
	}

	return result, nil
}

// parseMultimap parses CQL multimap format (string -> string list)
func parseMultimap(data []byte, result *CassandraResult) {
	if len(data) < 2 {
		return
	}

	numPairs := binary.BigEndian.Uint16(data[0:2])
	offset := 2

	for i := uint16(0); i < numPairs && offset < len(data); i++ {
		// Read key
		if offset+2 > len(data) {
			break
		}
		keyLen := binary.BigEndian.Uint16(data[offset : offset+2])
		offset += 2

		if offset+int(keyLen) > len(data) {
			break
		}
		key := string(data[offset : offset+int(keyLen)])
		offset += int(keyLen)

		// Read value list
		if offset+2 > len(data) {
			break
		}
		numValues := binary.BigEndian.Uint16(data[offset : offset+2])
		offset += 2

		var values []string
		for j := uint16(0); j < numValues && offset < len(data); j++ {
			if offset+2 > len(data) {
				break
			}
			valueLen := binary.BigEndian.Uint16(data[offset : offset+2])
			offset += 2

			if offset+int(valueLen) > len(data) {
				break
			}
			value := string(data[offset : offset+int(valueLen)])
			offset += int(valueLen)
			values = append(values, value)
		}

		// Store based on key
		if len(values) > 0 {
			switch key {
			case "CQL_VERSION":
				result.CQLVersions = values
			case "COMPRESSION":
				result.Compression = values
			default:
				result.SupportedOptions[key] = values[0]
			}
		}
	}
}

// getSystemInfo attempts to query system tables for additional info
func getSystemInfo(conn net.Conn, version byte, result *CassandraResult) {
	// Query system.local for cluster info
	query := "SELECT cluster_name, data_center, release_version FROM system.local"

	// Build QUERY frame
	queryBytes := []byte(query)
	queryLen := len(queryBytes)

	// String length (4 bytes) + string
	bodyLen := 4 + queryLen + 2 + 2 // string + consistency + flags

	frame := make([]byte, 9+bodyLen)
	frame[0] = version
	frame[1] = 0x00 // Flags
	frame[2] = 0x00 // Stream ID
	frame[3] = 0x02 // Stream ID
	frame[4] = 0x07 // Opcode: QUERY
	binary.BigEndian.PutUint32(frame[5:9], uint32(bodyLen))

	// Long string (query)
	binary.BigEndian.PutUint32(frame[9:13], uint32(queryLen))
	copy(frame[13:], queryBytes)

	// Consistency level (ONE = 0x0001)
	binary.BigEndian.PutUint16(frame[13+queryLen:15+queryLen], 0x0001)
	// Flags
	frame[15+queryLen] = 0x00

	if _, err := conn.Write(frame); err != nil {
		return
	}

	response := make([]byte, 4096)
	n, err := conn.Read(response)
	if err != nil || n < 9 {
		return
	}

	opcode := response[4]
	bodyLength := binary.BigEndian.Uint32(response[5:9])

	// Cap body length to prevent excessive allocation
	if bodyLength > 65536 {
		return
	}

	// RESULT response (opcode 0x08)
	if opcode == 0x08 && bodyLength > 0 && n >= int(9+bodyLength) {
		// Parse result - this is simplified, full parsing is complex
		bodyData := response[9 : 9+bodyLength]
		if len(bodyData) > 4 {
			resultKind := binary.BigEndian.Uint32(bodyData[0:4])
			// ROWS result (kind = 0x0002)
			if resultKind == 0x0002 {
				// Try to extract cluster name from first row
				// This is a simplified extraction
				offset := 4
				// Skip metadata
				if offset+4 <= len(bodyData) {
					flags := binary.BigEndian.Uint32(bodyData[offset : offset+4])
					offset += 4
					colCount := binary.BigEndian.Uint32(bodyData[offset : offset+4])
					offset += 4

					// Skip column specifications
					if flags&0x0001 == 0 && colCount <= 10 {
						// Has global keyspace and table
						if offset+2 <= len(bodyData) {
							ksLen := binary.BigEndian.Uint16(bodyData[offset : offset+2])
							offset += 2 + int(ksLen)
						}
						if offset+2 <= len(bodyData) {
							tableLen := binary.BigEndian.Uint16(bodyData[offset : offset+2])
							offset += 2 + int(tableLen)
						}

						// Skip column specs
						for i := uint32(0); i < colCount && offset < len(bodyData); i++ {
							if offset+2 > len(bodyData) {
								break
							}
							nameLen := binary.BigEndian.Uint16(bodyData[offset : offset+2])
							offset += 2 + int(nameLen) + 2 // name + type
						}
					}

					// Read rows count
					if offset+4 <= len(bodyData) {
						rowCount := binary.BigEndian.Uint32(bodyData[offset : offset+4])
						offset += 4

						if rowCount > 0 && offset+4 <= len(bodyData) {
							// First column (cluster_name)
							valueLen := int32(binary.BigEndian.Uint32(bodyData[offset : offset+4]))
							offset += 4
							if valueLen > 0 && valueLen < 256 && offset+int(valueLen) <= len(bodyData) {
								result.ClusterName = string(bodyData[offset : offset+int(valueLen)])
							}
						}
					}
				}
			}
		}
	}
}
