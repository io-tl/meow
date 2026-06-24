package modules

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"time"

	"meow/grabber/pkg/enrichment/modules/helpers"
)

// RedisModule implements the Redis enrichment module
type RedisModule struct {
	BaseModule
}

// RedisResult represents the enriched Redis data
type RedisResult struct {
	Protocol string            `json:"protocol"`
	Info     map[string]string `json:"info,omitempty"`
	Version  string            `json:"version,omitempty"`
	Mode     string            `json:"mode,omitempty"` // standalone, cluster, sentinel
	Error    string            `json:"error,omitempty"`
}

func init() {
	Register(&RedisModule{
		BaseModule: NewBaseModule(
			"redis",
			[]string{},
			true, // Should enrich
			10*time.Second,
		),
	})
}

func (m *RedisModule) Scan(ip string, port int) (interface{}, error) {
	return scanRedis(ip, port, m.DefaultTimeout())
}

// scanRedis performs Redis enrichment
func scanRedis(ip string, port int, timeout time.Duration) (*RedisResult, error) {
	result := &RedisResult{
		Protocol: "redis",
		Info:     make(map[string]string),
	}

	// Connect using helper
	conn, err := helpers.DialTCP(ip, port, timeout)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Try INFO command (works without authentication for basic info)
	_, err = conn.Write([]byte("INFO\r\n"))
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	// Read response
	line, err := reader.ReadString('\n')
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	// Check if we got a valid Redis response
	if strings.HasPrefix(line, "$") {
		// Bulk string response - read the info data
		// Parse the length
		length := 0
		fmt.Sscanf(line, "$%d", &length)
		if length > 0 && length < 100000 {
			// Read the actual data
			if length > 1000000 {
				result.Error = "INFO response too large"
				return result, nil
			}
			infoData := make([]byte, length)
			if _, err := io.ReadFull(reader, infoData); err == nil {
				_, _ = io.ReadFull(reader, make([]byte, 2))
				// Parse INFO response using helper
				lines := strings.Split(string(infoData), "\n")
				for _, l := range lines {
					l = strings.TrimSpace(l)
					if l == "" || strings.HasPrefix(l, "#") {
						continue
					}
					// Parse key-value using helper
					key, value := helpers.ParseKeyValue(l, ":")
					if key != "" {
						result.Info[key] = value

						// Extract specific fields
						if key == "redis_version" {
							result.Version = value
						} else if key == "redis_mode" {
							result.Mode = value
						}
					}
				}
			} else {
				result.Error = err.Error()
			}
		}
	} else if strings.HasPrefix(line, "-NOAUTH") {
		// Authentication required
		result.Error = "Authentication required"
	} else if strings.HasPrefix(line, "-") {
		// Error response
		result.Error = strings.TrimSpace(line[1:])
	}

	// Send QUIT
	conn.Write([]byte("QUIT\r\n"))

	return result, nil
}
