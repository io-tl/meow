package modules

import (
	"bufio"
	"strings"
	"time"

	"meow/grabber/pkg/enrichment/modules/helpers"
)

// IRCModule implements the IRC enrichment module
type IRCModule struct {
	BaseModule
}

// IRCResult represents the enriched IRC data
type IRCResult struct {
	Protocol string   `json:"protocol"`
	Server   string   `json:"server,omitempty"`
	Version  string   `json:"version,omitempty"`
	MOTD     []string `json:"motd,omitempty"`
	Error    string   `json:"error,omitempty"`
}

func init() {
	Register(&IRCModule{
		BaseModule: NewBaseModule(
			"irc",
			[]string{},
			true,
			10*time.Second,
		),
	})
}

func (m *IRCModule) Scan(ip string, port int) (interface{}, error) {
	return scanIRC(ip, port, m.DefaultTimeout())
}

func scanIRC(ip string, port int, timeout time.Duration) (*IRCResult, error) {
	result := &IRCResult{
		Protocol: "irc",
	}

	conn, err := helpers.DialTCP(ip, port, timeout)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	defer conn.Close()
	reader := bufio.NewReader(conn)

	// Send NICK and USER
	conn.Write([]byte("NICK scanner\r\n"))
	conn.Write([]byte("USER scanner 0 * :Scanner\r\n"))

	// Read responses
	for i := 0; i < 20; i++ {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}

		line = strings.TrimSpace(line)

		// Parse IRC response
		if strings.Contains(line, "004") { // RPL_MYINFO
			parts := strings.Fields(line)
			if len(parts) > 1 {
				result.Server = parts[1]
			}
			if len(parts) > 2 {
				result.Version = parts[2]
			}
		}

		// MOTD
		if strings.Contains(line, "372") || strings.Contains(line, "375") {
			result.MOTD = append(result.MOTD, line)
		}

		// End of MOTD
		if strings.Contains(line, "376") {
			break
		}
	}

	conn.Write([]byte("QUIT\r\n"))
	return result, nil
}
