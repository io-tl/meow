package modules

import (
	"bufio"
	"strings"
	"time"

	"meow/grabber/pkg/enrichment/modules/helpers"
)

// MPDModule implements the Music Player Daemon enrichment module
type MPDModule struct {
	BaseModule
}

type MPDResult struct {
	Protocol string            `json:"protocol"`
	Version  string            `json:"version,omitempty"`
	Status   map[string]string `json:"status,omitempty"`
	Error    string            `json:"error,omitempty"`
}

func init() {
	Register(&MPDModule{
		BaseModule: NewBaseModule("mpd", []string{}, true, 10*time.Second),
	})
}

func (m *MPDModule) Scan(ip string, port int) (interface{}, error) {
	result := &MPDResult{Protocol: "mpd", Status: make(map[string]string)}
	conn, err := helpers.DialTCP(ip, port, m.DefaultTimeout())
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	defer conn.Close()
	reader := bufio.NewReader(conn)

	// Read greeting
	greeting, _ := reader.ReadString('\n')
	if strings.HasPrefix(greeting, "OK MPD") {
		result.Version = strings.TrimSpace(strings.TrimPrefix(greeting, "OK MPD"))

		// Get status
		conn.Write([]byte("status\n"))
		for {
			line, err := reader.ReadString('\n')
			if err != nil || strings.HasPrefix(line, "OK") {
				break
			}
			parts := strings.SplitN(strings.TrimSpace(line), ": ", 2)
			if len(parts) == 2 {
				result.Status[parts[0]] = parts[1]
			}
		}
	}

	return result, nil
}
