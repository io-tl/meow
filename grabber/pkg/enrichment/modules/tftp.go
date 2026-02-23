package modules

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"meow/grabber/pkg/enrichment/modules/helpers"
)

// TFTPModule implements the TFTP enrichment module
type TFTPModule struct {
	BaseModule
}

type TFTPResult struct {
	Protocol      string   `json:"protocol"`
	Response      bool     `json:"response"`
	FoundFiles    []string `json:"found_files,omitempty"`
	ErrorMessages []string `json:"error_messages,omitempty"`
	ReadAllowed   bool     `json:"read_allowed"`
	Error         string   `json:"error,omitempty"`
}

func init() {
	Register(&TFTPModule{
		BaseModule: NewBaseModule("tftp", []string{}, true, 10*time.Second),
	})
}

func (m *TFTPModule) Scan(ip string, port int) (interface{}, error) {
	result := &TFTPResult{Protocol: "tftp"}

	// Common files to probe
	commonFiles := []string{
		"boot.ini",
		"config.txt",
		"router.cfg",
		"running-config",
		"startup-config",
		"config.cfg",
		"boot.cfg",
		"system.ini",
		"network.cfg",
	}

	for _, filename := range commonFiles {
		found, errMsg := probeTFTPFile(ip, port, filename, m.DefaultTimeout())
		if found {
			result.FoundFiles = append(result.FoundFiles, filename)
			result.ReadAllowed = true
		}
		if errMsg != "" && !contains(result.ErrorMessages, errMsg) {
			result.ErrorMessages = append(result.ErrorMessages, errMsg)
		}
		if found || errMsg != "" {
			result.Response = true
		}
	}

	// If nothing found, try a basic probe
	if !result.Response {
		found, errMsg := probeTFTPFile(ip, port, "test", m.DefaultTimeout())
		if errMsg != "" {
			result.Response = true
			result.ErrorMessages = append(result.ErrorMessages, errMsg)
		}
		if found {
			result.Response = true
		}
	}

	if !result.Response {
		result.Error = "No TFTP response"
	}

	return result, nil
}

// probeTFTPFile attempts to read a file via TFTP
func probeTFTPFile(ip string, port int, filename string, timeout time.Duration) (bool, string) {
	conn, err := helpers.DialUDP(ip, port, timeout)
	if err != nil {
		return false, ""
	}
	defer conn.Close()

	// Build TFTP Read Request (RRQ)
	rrq := []byte{0x00, 0x01} // Opcode: RRQ
	rrq = append(rrq, []byte(filename)...)
	rrq = append(rrq, 0x00) // Null terminator
	rrq = append(rrq, []byte("octet")...)
	rrq = append(rrq, 0x00) // Null terminator

	_, err = conn.Write(rrq)
	if err != nil {
		return false, ""
	}

	response := make([]byte, 516)
	n, err := conn.Read(response)
	if err != nil || n < 4 {
		return false, ""
	}

	opcode := binary.BigEndian.Uint16(response[0:2])

	switch opcode {
	case 3: // DATA
		// File exists and we got data
		return true, ""
	case 5: // ERROR
		// Parse error message
		errorCode := binary.BigEndian.Uint16(response[2:4])
		errorMsg := ""
		if n > 4 {
			// Extract error message (null-terminated string)
			msgBytes := response[4:n]
			for i, b := range msgBytes {
				if b == 0 {
					errorMsg = string(msgBytes[:i])
					break
				}
			}
		}
		if errorMsg == "" {
			errorMsg = getTFTPErrorMessage(errorCode)
		}
		return false, errorMsg
	}

	return false, ""
}

// getTFTPErrorMessage returns the standard TFTP error message for a code
func getTFTPErrorMessage(code uint16) string {
	switch code {
	case 0:
		return "Not defined"
	case 1:
		return "File not found"
	case 2:
		return "Access violation"
	case 3:
		return "Disk full"
	case 4:
		return "Illegal TFTP operation"
	case 5:
		return "Unknown transfer ID"
	case 6:
		return "File already exists"
	case 7:
		return "No such user"
	default:
		return fmt.Sprintf("Error code %d", code)
	}
}

// contains checks if a string slice contains a string
func contains(slice []string, str string) bool {
	for _, s := range slice {
		if strings.EqualFold(s, str) {
			return true
		}
	}
	return false
}
