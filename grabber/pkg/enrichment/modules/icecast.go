package modules

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// IcecastModule implements the Icecast enrichment module
type IcecastModule struct {
	BaseModule
}

type IcecastResult struct {
	Protocol    string            `json:"protocol"`
	Server      string            `json:"server,omitempty"`
	Version     string            `json:"version,omitempty"`
	Admin       string            `json:"admin,omitempty"`
	Host        string            `json:"host,omitempty"`
	Location    string            `json:"location,omitempty"`
	Listeners   int               `json:"listeners,omitempty"`
	Sources     int               `json:"sources,omitempty"`
	Streams     []IcecastStream   `json:"streams,omitempty"`
	ServerInfo  map[string]string `json:"server_info,omitempty"`
	Error       string            `json:"error,omitempty"`
}

type IcecastStream struct {
	Mount     string `json:"mount"`
	Listeners int    `json:"listeners,omitempty"`
	Bitrate   string `json:"bitrate,omitempty"`
	Genre     string `json:"genre,omitempty"`
	Title     string `json:"title,omitempty"`
}

func init() {
	Register(&IcecastModule{
		BaseModule: NewBaseModule("icecast", []string{"shoutcast"}, true, 10*time.Second),
	})
}

func (m *IcecastModule) Scan(ip string, port int) (interface{}, error) {
	result := &IcecastResult{
		Protocol:   "icecast",
		ServerInfo: make(map[string]string),
	}
	client := &http.Client{Timeout: m.DefaultTimeout()}

	// Try JSON stats endpoint first (Icecast 2.4+)
	resp, err := client.Get(fmt.Sprintf("http://%s:%d/status-json.xsl", ip, port))
	if err == nil {
		defer resp.Body.Close()
		result.Server = resp.Header.Get("Server")

		body, _ := io.ReadAll(resp.Body)
		var statsData map[string]interface{}
		if json.Unmarshal(body, &statsData) == nil {
			if icestats, ok := statsData["icestats"].(map[string]interface{}); ok {
				// Server info
				if admin, ok := icestats["admin"].(string); ok {
					result.Admin = admin
				}
				if host, ok := icestats["host"].(string); ok {
					result.Host = host
				}
				if location, ok := icestats["location"].(string); ok {
					result.Location = location
				}
				if serverID, ok := icestats["server_id"].(string); ok {
					result.Version = serverID
				}

				// Sources
				if sources, ok := icestats["source"].([]interface{}); ok {
					result.Sources = len(sources)
					for _, source := range sources {
						if s, ok := source.(map[string]interface{}); ok {
							stream := IcecastStream{}
							if mount, ok := s["listenurl"].(string); ok {
								stream.Mount = mount
							}
							if listeners, ok := s["listeners"].(float64); ok {
								stream.Listeners = int(listeners)
								result.Listeners += int(listeners)
							}
							if bitrate, ok := s["bitrate"].(float64); ok {
								stream.Bitrate = fmt.Sprintf("%dkbps", int(bitrate))
							}
							if genre, ok := s["genre"].(string); ok {
								stream.Genre = genre
							}
							if title, ok := s["title"].(string); ok {
								stream.Title = title
							}
							result.Streams = append(result.Streams, stream)
						}
					}
				}
			}
		}
		return result, nil
	}

	// Fallback to basic status check
	resp, err = client.Get(fmt.Sprintf("http://%s:%d/status.xsl", ip, port))
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	defer resp.Body.Close()

	result.Server = resp.Header.Get("Server")
	if result.Server != "" {
		result.Version = result.Server
	}

	// Try to get some info from the response body
	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)
	if strings.Contains(bodyStr, "Icecast") {
		result.ServerInfo["detected"] = "icecast"
	}

	return result, nil
}
