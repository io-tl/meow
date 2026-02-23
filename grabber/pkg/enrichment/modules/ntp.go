package modules

import (
	"encoding/binary"
	"fmt"
	"time"

	"meow/grabber/pkg/enrichment/modules/helpers"
)

// NTPModule implements the NTP enrichment module
type NTPModule struct {
	BaseModule
}

// NTPResult represents the enriched NTP data
type NTPResult struct {
	Protocol      string    `json:"protocol"`
	Version       int       `json:"version,omitempty"`
	Stratum       int       `json:"stratum,omitempty"`
	ReferenceID   string    `json:"reference_id,omitempty"`
	ReferenceTime time.Time `json:"reference_time,omitempty"`
	Error         string    `json:"error,omitempty"`
}

func init() {
	Register(&NTPModule{
		BaseModule: NewBaseModule(
			"ntp",
			[]string{},
			true, // Should enrich
			10*time.Second,
		),
	})
}

func (m *NTPModule) Scan(ip string, port int) (interface{}, error) {
	return scanNTP(ip, port, m.DefaultTimeout())
}

// scanNTP performs NTP enrichment
func scanNTP(ip string, port int, timeout time.Duration) (*NTPResult, error) {
	result := &NTPResult{
		Protocol: "ntp",
	}

	conn, err := helpers.DialUDP(ip, port, timeout)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	defer conn.Close()

	// Build NTP request packet (48 bytes)
	request := make([]byte, 48)
	// LI=0 (no warning), VN=3 (version 3), Mode=3 (client)
	request[0] = 0x1b // 00 011 011

	_, err = conn.Write(request)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	// Read response
	response := make([]byte, 48)
	n, err := conn.Read(response)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	if n >= 48 {
		// Parse NTP response
		// First byte: LI (2 bits), VN (3 bits), Mode (3 bits)
		version := (response[0] >> 3) & 0x07
		result.Version = int(version)

		// Stratum (1 byte)
		result.Stratum = int(response[1])

		// Reference ID (4 bytes)
		refID := binary.BigEndian.Uint32(response[12:16])
		result.ReferenceID = fmt.Sprintf("0x%08x", refID)

		// Reference timestamp (bytes 16-23)
		refTimestamp := binary.BigEndian.Uint64(response[16:24])
		if refTimestamp > 0 {
			// NTP epoch is January 1, 1900
			ntpEpoch := time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC)
			seconds := refTimestamp >> 32
			result.ReferenceTime = ntpEpoch.Add(time.Duration(seconds) * time.Second)
		}
	}

	return result, nil
}
