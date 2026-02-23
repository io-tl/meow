package modules

import (
	"bufio"
	"strings"
	"time"

	"meow/grabber/pkg/enrichment/modules/helpers"
)

// MemcachedModule implements the Memcached enrichment module
type MemcachedModule struct {
	BaseModule
}

// MemcachedResult represents the enriched Memcached data
type MemcachedResult struct {
	Protocol string            `json:"protocol"`
	Version  string            `json:"version,omitempty"`
	Stats    map[string]string `json:"stats,omitempty"`
	Error    string            `json:"error,omitempty"`
}

func init() {
	Register(&MemcachedModule{
		BaseModule: NewBaseModule(
			"memcached",
			[]string{"memcache"},
			true, // Should enrich
			10*time.Second,
		),
	})
}

func (m *MemcachedModule) Scan(ip string, port int) (interface{}, error) {
	return scanMemcached(ip, port, m.DefaultTimeout())
}

// scanMemcached performs Memcached enrichment
func scanMemcached(ip string, port int, timeout time.Duration) (*MemcachedResult, error) {
	result := &MemcachedResult{
		Protocol: "memcached",
		Stats:    make(map[string]string),
	}

	// Connect using helper
	conn, err := helpers.DialTCP(ip, port, timeout)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Send stats command
	_, err = conn.Write([]byte("stats\r\n"))
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	// Read stats response
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}

		line = strings.TrimSpace(line)

		// End of stats
		if line == "END" {
			break
		}

		// Parse stat line: STAT key value
		if strings.HasPrefix(line, "STAT ") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				key := parts[1]
				value := parts[2]
				result.Stats[key] = value

				// Extract version
				if key == "version" {
					result.Version = value
				}
			}
		}
	}

	// Send quit
	_, err = conn.Write([]byte("quit\r\n"))
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	if result.Version == "" && len(result.Stats) == 0 {
		result.Error = "No valid Memcached response"
	}

	return result, nil
}
