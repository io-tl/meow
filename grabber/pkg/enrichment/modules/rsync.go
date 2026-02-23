package modules

import (
	"bufio"
	"strings"
	"time"

	"meow/grabber/pkg/enrichment/modules/helpers"
)

// RsyncModule implements the Rsync enrichment module
type RsyncModule struct {
	BaseModule
}

// RsyncResult represents the enriched Rsync data
type RsyncResult struct {
	Protocol string   `json:"protocol"`
	Version  string   `json:"version,omitempty"`
	MOTD     string   `json:"motd,omitempty"`
	Modules  []string `json:"modules,omitempty"`
	Error    string   `json:"error,omitempty"`
}

func init() {
	Register(&RsyncModule{
		BaseModule: NewBaseModule(
			"rsync",
			[]string{},
			true,
			10*time.Second,
		),
	})
}

func (m *RsyncModule) Scan(ip string, port int) (interface{}, error) {
	return scanRsync(ip, port, m.DefaultTimeout())
}

func scanRsync(ip string, port int, timeout time.Duration) (*RsyncResult, error) {
	result := &RsyncResult{
		Protocol: "rsync",
	}

	conn, err := helpers.DialTCP(ip, port, timeout)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	defer conn.Close()
	reader := bufio.NewReader(conn)

	// Read server greeting
	greeting, err := reader.ReadString('\n')
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	greeting = strings.TrimSpace(greeting)
	if strings.HasPrefix(greeting, "@RSYNCD:") {
		result.Version = strings.TrimPrefix(greeting, "@RSYNCD: ")

		// Request module list
		_, err = conn.Write([]byte("#list\n"))
		if err != nil {
			result.Error = err.Error()
			return result, err
		}

		// Read modules
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				break
			}
			line = strings.TrimSpace(line)
			if line == "@RSYNCD: EXIT" || line == "" {
				break
			}
			if !strings.HasPrefix(line, "@") {
				parts := strings.Fields(line)
				if len(parts) > 0 {
					result.Modules = append(result.Modules, parts[0])
				}
			}
		}
	}

	return result, nil
}
