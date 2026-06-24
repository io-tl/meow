package modules

import (
	"time"

	"meow/grabber/pkg/enrichment/modules/helpers"
)

// BannerModule implements a generic banner grabber
type BannerModule struct {
	BaseModule
}

// BannerResult represents the enriched banner data
type BannerResult struct {
	Protocol string `json:"protocol"`
	Banner   string `json:"banner,omitempty"`
	Length   int    `json:"length"`
	Error    string `json:"error,omitempty"`
}

func init() {
	Register(&BannerModule{
		BaseModule: NewBaseModule(
			"banner",
			[]string{},
			true, // Should enrich
			10*time.Second,
		),
	})
}

func (m *BannerModule) Scan(ip string, port int) (interface{}, error) {
	return scanBanner(ip, port, m.DefaultTimeout())
}

// scanBanner performs generic banner grabbing
func scanBanner(ip string, port int, timeout time.Duration) (*BannerResult, error) {
	result := &BannerResult{
		Protocol: "banner",
	}

	// DialTCP sets a deadline on the connection, so reads will timeout automatically
	conn, err := helpers.DialTCP(ip, port, timeout)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	defer conn.Close()

	// Synchronous read — the deadline from DialTCP ensures we don't block forever
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil && n == 0 {
		// If the server closes immediately, return empty result without error
		if err.Error() == "EOF" {
			return result, nil
		}
		result.Error = err.Error()
		return result, err
	}

	result.Banner = string(buf[:n])
	result.Length = n

	return result, nil
}
