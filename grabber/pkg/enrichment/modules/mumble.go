package modules

import (
	"encoding/binary"
	"fmt"
	"time"

	"meow/grabber/pkg/enrichment/modules/helpers"
)

// MumbleModule implements the Mumble enrichment module
type MumbleModule struct {
	BaseModule
}

type MumbleResult struct {
	Protocol       string `json:"protocol"`
	Version        string `json:"version,omitempty"`
	VersionMajor   int    `json:"version_major,omitempty"`
	VersionMinor   int    `json:"version_minor,omitempty"`
	VersionPatch   int    `json:"version_patch,omitempty"`
	Ping           bool   `json:"ping"`
	Users          uint32 `json:"users,omitempty"`
	MaxUsers       uint32 `json:"max_users,omitempty"`
	Bandwidth      uint32 `json:"bandwidth,omitempty"`
	Error          string `json:"error,omitempty"`
}

func init() {
	Register(&MumbleModule{
		BaseModule: NewBaseModule("mumble", []string{}, true, 10*time.Second),
	})
}

func (m *MumbleModule) Scan(ip string, port int) (interface{}, error) {
	result := &MumbleResult{Protocol: "mumble"}
	conn, err := helpers.DialUDP(ip, port, m.DefaultTimeout())
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	defer conn.Close()

	// Mumble ping packet
	ping := make([]byte, 12)
	binary.BigEndian.PutUint32(ping[0:4], uint32(time.Now().Unix()))

	if _, err := conn.Write(ping); err != nil {
		result.Error = err.Error()
		return result, err
	}

	response := make([]byte, 24)
	n, err := conn.Read(response)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	if n < 4 {
		result.Error = "Mumble response too short"
		return result, nil
	}

	result.Ping = true

	// Parse Mumble ping response
	version := binary.BigEndian.Uint32(response[0:4])

	// Version format: (major << 16) | (minor << 8) | patch
	result.VersionMajor = int((version >> 16) & 0xFF)
	result.VersionMinor = int((version >> 8) & 0xFF)
	result.VersionPatch = int(version & 0xFF)
	result.Version = fmt.Sprintf("%d.%d.%d", result.VersionMajor, result.VersionMinor, result.VersionPatch)

	// Parse additional info - need at least 20 bytes for all fields
	if n >= 20 {
		// Skip timestamp echo (8 bytes)
		result.Users = binary.BigEndian.Uint32(response[8:12])
		result.MaxUsers = binary.BigEndian.Uint32(response[12:16])
		result.Bandwidth = binary.BigEndian.Uint32(response[16:20])
	}

	return result, nil
}
