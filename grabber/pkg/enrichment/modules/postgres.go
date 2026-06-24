package modules

import (
	"encoding/binary"
	"time"

	"meow/grabber/pkg/enrichment/modules/helpers"
)

// PostgresModule implements the PostgreSQL enrichment module
type PostgresModule struct {
	BaseModule
}

// PostgresResult represents the enriched PostgreSQL data
type PostgresResult struct {
	Protocol     string            `json:"protocol"`
	SSLSupported bool              `json:"ssl_supported"`
	Parameters   map[string]string `json:"parameters,omitempty"`
	Error        string            `json:"error,omitempty"`
}

func init() {
	Register(&PostgresModule{
		BaseModule: NewBaseModule(
			"postgres",
			[]string{"postgresql"},
			true, // Should enrich
			10*time.Second,
		),
	})
}

func (m *PostgresModule) Scan(ip string, port int) (interface{}, error) {
	return scanPostgres(ip, port, m.DefaultTimeout())
}

// scanPostgres performs PostgreSQL enrichment
func scanPostgres(ip string, port int, timeout time.Duration) (*PostgresResult, error) {
	result := &PostgresResult{
		Protocol:   "postgres",
		Parameters: make(map[string]string),
	}

	// Connect using helper
	conn, err := helpers.DialTCP(ip, port, timeout)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	defer conn.Close()

	// Test SSL support
	// SSL request message: length (4 bytes) + SSL request code (4 bytes)
	sslRequest := make([]byte, 8)
	binary.BigEndian.PutUint32(sslRequest[0:4], 8)        // Length
	binary.BigEndian.PutUint32(sslRequest[4:8], 80877103) // SSL request code

	_, err = conn.Write(sslRequest)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	// Read SSL response (1 byte: 'S' = supported, 'N' = not supported)
	sslResponse := make([]byte, 1)
	_, err = conn.Read(sslResponse)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	result.SSLSupported = (sslResponse[0] == 'S')

	// Try to get more info with a startup message
	// Note: This will fail without proper authentication, but we can still get server parameters

	return result, nil
}
