package modules

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"

	"meow/grabber/pkg/enrichment/modules/helpers"
)

// X11Module implements the X11 enrichment module
type X11Module struct {
	BaseModule
}

type X11Result struct {
	Protocol         string   `json:"protocol"`
	Version          string   `json:"version,omitempty"`
	Vendor           string   `json:"vendor,omitempty"`
	Release          uint32   `json:"release,omitempty"`
	MaxRequestLength uint16   `json:"max_request_length,omitempty"`
	Screens          int      `json:"screens,omitempty"`
	PixmapFormats    int      `json:"pixmap_formats,omitempty"`
	AuthRequired     bool     `json:"auth_required"`
	AuthMethods      []string `json:"auth_methods,omitempty"`
	Error            string   `json:"error,omitempty"`
}

func init() {
	Register(&X11Module{
		BaseModule: NewBaseModule("x11", []string{"x-window", "xorg"}, true, 10*time.Second),
	})
}

func (m *X11Module) Scan(ip string, port int) (interface{}, error) {
	result := &X11Result{Protocol: "x11"}
	conn, err := helpers.DialTCP(ip, port, m.DefaultTimeout())
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	defer conn.Close()

	// Build X11 setup request
	// Format: byte-order + pad + protocol-major + protocol-minor + auth-proto-name-len + auth-proto-data-len + pad
	setupRequest := new(bytes.Buffer)

	// Byte order: 'B' = MSB first, 'l' = LSB first
	setupRequest.WriteByte('l') // LSB first (little-endian)
	setupRequest.WriteByte(0)   // Pad

	// Protocol version (11.0)
	binary.Write(setupRequest, binary.LittleEndian, uint16(11)) // Major version
	binary.Write(setupRequest, binary.LittleEndian, uint16(0))  // Minor version

	// Authorization protocol name length
	binary.Write(setupRequest, binary.LittleEndian, uint16(0)) // No auth
	// Authorization protocol data length
	binary.Write(setupRequest, binary.LittleEndian, uint16(0)) // No auth data

	// Pad to multiple of 4
	setupRequest.WriteByte(0)
	setupRequest.WriteByte(0)

	_, err = conn.Write(setupRequest.Bytes())
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	// Read response header (first byte indicates success/failure)
	responseHeader := make([]byte, 8)
	n, err := conn.Read(responseHeader)
	if err != nil || n < 8 {
		result.Error = "Failed to read X11 response"
		return result, err
	}

	status := responseHeader[0]

	switch status {
	case 0: // Failed
		result.AuthRequired = true
		// Read failure reason
		reasonLen := responseHeader[1]
		majorVersion := binary.LittleEndian.Uint16(responseHeader[2:4])
		minorVersion := binary.LittleEndian.Uint16(responseHeader[4:6])
		result.Version = fmt.Sprintf("%d.%d", majorVersion, minorVersion)

		additionalDataLen := binary.LittleEndian.Uint16(responseHeader[6:8])
		if reasonLen > 0 && additionalDataLen > 0 {
			reasonData := make([]byte, int(additionalDataLen)*4)
			conn.Read(reasonData)
			if int(reasonLen) <= len(reasonData) {
				result.Error = string(reasonData[:reasonLen])
			}
		}
		result.AuthMethods = []string{"required"}

	case 1: // Success
		result.AuthRequired = false
		// Read additional setup data length
		additionalDataLen := binary.LittleEndian.Uint16(responseHeader[6:8])

		// Read the rest of the setup data
		setupData := make([]byte, int(additionalDataLen)*4)
		n, err = conn.Read(setupData)
		if err != nil || n < len(setupData) {
			return result, nil
		}

		// Parse setup data
		if len(setupData) >= 32 {
			majorVersion := binary.LittleEndian.Uint16(responseHeader[2:4])
			minorVersion := binary.LittleEndian.Uint16(responseHeader[4:6])
			result.Version = fmt.Sprintf("%d.%d", majorVersion, minorVersion)

			result.Release = binary.LittleEndian.Uint32(setupData[0:4])
			result.MaxRequestLength = binary.LittleEndian.Uint16(setupData[12:14])

			vendorLen := binary.LittleEndian.Uint16(setupData[16:18])
			numFormats := setupData[20]
			numScreens := setupData[21]

			result.PixmapFormats = int(numFormats)
			result.Screens = int(numScreens)

			// Extract vendor string
			vendorOffset := 32
			if vendorOffset+int(vendorLen) <= len(setupData) {
				result.Vendor = string(setupData[vendorOffset : vendorOffset+int(vendorLen)])
			}
		}

	case 2: // Authenticate
		result.AuthRequired = true
		result.AuthMethods = []string{"authenticate"}
		additionalDataLen := binary.LittleEndian.Uint16(responseHeader[6:8])
		authData := make([]byte, int(additionalDataLen)*4)
		conn.Read(authData)
		result.Error = "Authentication required"

	default:
		result.Error = fmt.Sprintf("Unknown X11 response status: %d", status)
	}

	return result, nil
}
