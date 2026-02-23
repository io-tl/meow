package modules

import (
	"encoding/binary"
	"time"

	"meow/grabber/pkg/enrichment/modules/helpers"
)

// NFSModule implements the NFS enrichment module
type NFSModule struct {
	BaseModule
}

// NFSResult represents the enriched NFS data
type NFSResult struct {
	Protocol string   `json:"protocol"`
	Version  string   `json:"version,omitempty"`
	Exports  []string `json:"exports,omitempty"`
	Error    string   `json:"error,omitempty"`
}

func init() {
	Register(&NFSModule{
		BaseModule: NewBaseModule(
			"nfs",
			[]string{},
			true,
			10*time.Second,
		),
	})
}

func (m *NFSModule) Scan(ip string, port int) (interface{}, error) {
	return scanNFS(ip, port, m.DefaultTimeout())
}

func scanNFS(ip string, port int, timeout time.Duration) (*NFSResult, error) {
	result := &NFSResult{
		Protocol: "nfs",
	}

	// Connect using helper
	conn, err := helpers.DialTCP(ip, port, timeout)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	defer conn.Close()

	// RPC NULL call to mountd
	rpcCall := buildRPCNullCall()
	_, err = conn.Write(rpcCall)
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

	if n > 24 {
		result.Version = "detected"
	}

	return result, nil
}

func buildRPCNullCall() []byte {
	buf := make([]byte, 40)
	// RPC record marker
	binary.BigEndian.PutUint32(buf[0:4], 0x80000024) // Last fragment, 36 bytes
	// XID
	binary.BigEndian.PutUint32(buf[4:8], 1)
	// Message type: CALL (0)
	binary.BigEndian.PutUint32(buf[8:12], 0)
	// RPC version: 2
	binary.BigEndian.PutUint32(buf[12:16], 2)
	// Program: MOUNT (100005)
	binary.BigEndian.PutUint32(buf[16:20], 100005)
	// Program version: 3
	binary.BigEndian.PutUint32(buf[20:24], 3)
	// Procedure: NULL (0)
	binary.BigEndian.PutUint32(buf[24:28], 0)
	// Auth: NULL
	binary.BigEndian.PutUint32(buf[28:32], 0)
	binary.BigEndian.PutUint32(buf[32:36], 0)
	binary.BigEndian.PutUint32(buf[36:40], 0)
	return buf
}
