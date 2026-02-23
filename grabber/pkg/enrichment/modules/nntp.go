package modules

import (
	"bufio"
	"strings"
	"time"

	"meow/grabber/pkg/enrichment/modules/helpers"
)

// NNTPModule implements the NNTP enrichment module
type NNTPModule struct {
	BaseModule
}

type NNTPResult struct {
	Protocol     string   `json:"protocol"`
	Banner       string   `json:"banner,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
	Error        string   `json:"error,omitempty"`
}

func init() {
	Register(&NNTPModule{
		BaseModule: NewBaseModule("nntp", []string{}, true, 10*time.Second),
	})
}

func (m *NNTPModule) Scan(ip string, port int) (interface{}, error) {
	result := &NNTPResult{Protocol: "nntp"}
	conn, err := helpers.DialTCP(ip, port, m.DefaultTimeout())
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	defer conn.Close()
	reader := bufio.NewReader(conn)

	banner, _ := reader.ReadString('\n')
	result.Banner = strings.TrimSpace(banner)

	_, err = conn.Write([]byte("CAPABILITIES\r\n"))
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil || line == ".\r\n" {
			break
		}
		result.Capabilities = append(result.Capabilities, strings.TrimSpace(line))
	}

	_, err = conn.Write([]byte("QUIT\r\n"))
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	return result, nil
}
