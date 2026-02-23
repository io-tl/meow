package modules

import (
	"bufio"
	"strings"
	"time"

	"meow/grabber/pkg/enrichment/modules/helpers"
)

// LPDModule implements the LPD enrichment module
type LPDModule struct {
	BaseModule
}

type LPDResult struct {
	Protocol    string            `json:"protocol"`
	Queues      []string          `json:"queues,omitempty"`
	QueueStatus map[string]string `json:"queue_status,omitempty"`
	Error       string            `json:"error,omitempty"`
}

func init() {
	Register(&LPDModule{
		BaseModule: NewBaseModule("lpd", []string{"printer"}, true, 10*time.Second),
	})
}

func (m *LPDModule) Scan(ip string, port int) (interface{}, error) {
	result := &LPDResult{
		Protocol:    "lpd",
		QueueStatus: make(map[string]string),
	}
	conn, err := helpers.DialTCP(ip, port, m.DefaultTimeout())
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	defer conn.Close()
	reader := bufio.NewReader(conn)

	// Send queue list request (short format)
	conn.Write([]byte("\x04\n"))

	// Read response - parse actual queue names
	for {
		line, err := reader.ReadString('\n')
		if err != nil || len(line) == 0 {
			break
		}

		line = strings.TrimSpace(line)
		if len(line) == 0 {
			break
		}

		// LPD queue list format: "queuename state jobs"
		// or just queue names depending on server
		parts := strings.Fields(line)
		if len(parts) > 0 {
			queueName := parts[0]
			if queueName != "" {
				result.Queues = append(result.Queues, queueName)

				// Try to extract state and job count
				if len(parts) >= 2 {
					result.QueueStatus[queueName] = parts[1]
				}
			}
		}

		// Limit to reasonable number of queues
		if len(result.Queues) >= 50 {
			break
		}
	}

	// If no queues found, check if we at least got a response
	if len(result.Queues) == 0 {
		result.Error = "No queues found or access denied"
	}

	return result, nil
}
