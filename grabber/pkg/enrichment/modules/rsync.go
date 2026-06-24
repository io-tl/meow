package modules

import (
	"bufio"
	"fmt"
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
	Protocol     string            `json:"protocol"`
	Version      string            `json:"version,omitempty"`
	MOTD         string            `json:"motd,omitempty"`
	Modules      []string          `json:"modules,omitempty"`
	ModuleDetail []RsyncModuleInfo `json:"module_detail,omitempty"`
	Error        string            `json:"error,omitempty"`
}

type RsyncModuleInfo struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
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

		// Announce client protocol version before sending commands.
		_, err = fmt.Fprintf(conn, "@RSYNCD: %s\n", result.Version)
		if err != nil {
			result.Error = err.Error()
			return result, err
		}

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
				name, description := parseRsyncModuleLine(line)
				if name != "" {
					result.Modules = append(result.Modules, name)
					result.ModuleDetail = append(result.ModuleDetail, RsyncModuleInfo{
						Name:        name,
						Description: description,
					})
				}
			}
		}
	}

	return result, nil
}

func parseRsyncModuleLine(line string) (string, string) {
	if line == "" {
		return "", ""
	}

	if strings.Contains(line, "\t") {
		parts := strings.SplitN(line, "\t", 2)
		return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
	}

	fields := strings.Fields(line)
	if len(fields) == 0 {
		return "", ""
	}
	if len(fields) == 1 {
		return fields[0], ""
	}
	return fields[0], strings.TrimSpace(strings.TrimPrefix(line, fields[0]))
}
