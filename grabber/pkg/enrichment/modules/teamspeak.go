package modules

import (
	"bufio"
	"strings"
	"time"

	"meow/grabber/pkg/enrichment/modules/helpers"
)

// TeamSpeakModule implements the TeamSpeak enrichment module
type TeamSpeakModule struct {
	BaseModule
}

type TeamSpeakResult struct {
	Protocol string            `json:"protocol"`
	Version  string            `json:"version,omitempty"`
	Info     map[string]string `json:"info,omitempty"`
	Error    string            `json:"error,omitempty"`
}

func init() {
	Register(&TeamSpeakModule{
		BaseModule: NewBaseModule("teamspeak", []string{"ts3"}, true, 10*time.Second),
	})
}

func (m *TeamSpeakModule) Scan(ip string, port int) (interface{}, error) {
	result := &TeamSpeakResult{Protocol: "teamspeak", Info: make(map[string]string)}
	conn, err := helpers.DialTCP(ip, port, m.DefaultTimeout())
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	defer conn.Close()
	reader := bufio.NewReader(conn)

	// Read welcome message
	reader.ReadString('\n')
	reader.ReadString('\n')

	// Send serverinfo command
	conn.Write([]byte("serverinfo\n"))

	response, _ := reader.ReadString('\n')
	if strings.Contains(response, "virtualserver") {
		result.Version = "3"
		// Parse key=value pairs
		parts := strings.Fields(response)
		for _, part := range parts {
			kv := strings.SplitN(part, "=", 2)
			if len(kv) == 2 {
				result.Info[kv[0]] = kv[1]
			}
		}
	}

	conn.Write([]byte("quit\n"))
	return result, nil
}
