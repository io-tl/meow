package modules

import (
	"io"
	"time"

	"meow/grabber/pkg/enrichment/modules/helpers"
)

// MongoDBModule implements the MongoDB enrichment module
type MongoDBModule struct {
	BaseModule
}

// MongoDBResult represents the enriched MongoDB data
type MongoDBResult struct {
	Protocol string `json:"protocol"`
	Version  string `json:"version,omitempty"`
	BuildInfo map[string]interface{} `json:"build_info,omitempty"`
	Error    string `json:"error,omitempty"`
}

func init() {
	Register(&MongoDBModule{
		BaseModule: NewBaseModule(
			"mongodb",
			[]string{"mongo"},
			true, // Should enrich
			10*time.Second,
		),
	})
}

func (m *MongoDBModule) Scan(ip string, port int) (interface{}, error) {
	return scanMongoDB(ip, port, m.DefaultTimeout())
}

// scanMongoDB performs MongoDB enrichment
func scanMongoDB(ip string, port int, timeout time.Duration) (*MongoDBResult, error) {
	result := &MongoDBResult{
		Protocol: "mongodb",
		BuildInfo: make(map[string]interface{}),
	}

	// Connect using helper
	conn, err := helpers.DialTCP(ip, port, timeout)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	defer conn.Close()

	// Build a simple MongoDB OP_QUERY to get server info
	// MongoDB wire protocol: header (16 bytes) + query body
	// This is a simplified probe - proper implementation would use MongoDB driver

	// For now, just try to connect and detect if it's MongoDB by protocol
	// Send a malformed request and check the error response format
	probe := []byte{
		0x3a, 0x00, 0x00, 0x00, // message length (58 bytes)
		0x01, 0x00, 0x00, 0x00, // request ID
		0x00, 0x00, 0x00, 0x00, // response to
		0xd4, 0x07, 0x00, 0x00, // OP_QUERY opcode (2004)
		0x00, 0x00, 0x00, 0x00, // flags
		0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x24, 0x63, 0x6d, 0x64, 0x00, // admin.$cmd
		0x00, 0x00, 0x00, 0x00, // skip
		0xff, 0xff, 0xff, 0xff, // return
		// BSON document for {buildInfo: 1}
		0x1a, 0x00, 0x00, 0x00, // document size
		0x10, // int32 type
		0x62, 0x75, 0x69, 0x6c, 0x64, 0x49, 0x6e, 0x66, 0x6f, 0x00, // "buildInfo"
		0x01, 0x00, 0x00, 0x00, // value: 1
		0x00, // end of document
	}

	_, err = conn.Write(probe)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	// Try to read response using io.ReadFull to ensure we get all 16 bytes
	header := make([]byte, 16)
	if _, err = io.ReadFull(conn, header); err != nil {
		result.Error = err.Error()
		return result, err
	}

	// Parse response header using helpers
	messageLength := helpers.ReadUint32LE(header, 0)
	opCode := helpers.ReadUint32LE(header, 12)

	// Check if it looks like a MongoDB response (OP_REPLY = 1)
	if opCode == 1 && messageLength > 16 && messageLength < 100000 {
		result.Version = "detected" // Successfully identified as MongoDB
		// Could parse more details from the response, but this confirms it's MongoDB
	} else {
		result.Error = "Invalid MongoDB response"
	}

	return result, nil
}
