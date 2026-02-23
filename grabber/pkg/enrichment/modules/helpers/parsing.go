package helpers

import (
	"encoding/binary"
	"strings"
)

// ExtractNullTerminatedString extracts null-terminated string from byte slice
func ExtractNullTerminatedString(data []byte) string {
	for i, b := range data {
		if b == 0 {
			return string(data[:i])
		}
	}
	return string(data)
}

// ParseKeyValue parses "key: value" or "key=value" format lines
func ParseKeyValue(line, separator string) (string, string) {
	parts := strings.SplitN(line, separator, 2)
	if len(parts) != 2 {
		return "", ""
	}
	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
}

// ParseKeyValueMap parses multiple lines into key-value map
func ParseKeyValueMap(lines []string, separator string) map[string]string {
	result := make(map[string]string)
	for _, line := range lines {
		key, value := ParseKeyValue(line, separator)
		if key != "" {
			result[key] = value
		}
	}
	return result
}

// ContainsAny checks if string contains any of the substrings
func ContainsAny(s string, substrings []string) bool {
	for _, substr := range substrings {
		if strings.Contains(s, substr) {
			return true
		}
	}
	return false
}

// ExtractBetween extracts string between start and end markers
func ExtractBetween(s, start, end string) string {
	startIdx := strings.Index(s, start)
	if startIdx == -1 {
		return ""
	}
	startIdx += len(start)

	endIdx := strings.Index(s[startIdx:], end)
	if endIdx == -1 {
		return ""
	}

	return s[startIdx : startIdx+endIdx]
}

// ParseVersion extracts version from strings like "v1.2.3" or "1.2.3"
func ParseVersion(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "v")
	s = strings.TrimPrefix(s, "V")

	// Extract version-like pattern (numbers and dots)
	var version strings.Builder
	for _, ch := range s {
		if (ch >= '0' && ch <= '9') || ch == '.' {
			version.WriteRune(ch)
		} else if version.Len() > 0 {
			// Stop at first non-version character after version started
			break
		}
	}

	return version.String()
}

// ReadUint16BE reads uint16 in big-endian from byte slice
func ReadUint16BE(data []byte, offset int) uint16 {
	if offset+2 > len(data) {
		return 0
	}
	return binary.BigEndian.Uint16(data[offset : offset+2])
}

// ReadUint32BE reads uint32 in big-endian from byte slice
func ReadUint32BE(data []byte, offset int) uint32 {
	if offset+4 > len(data) {
		return 0
	}
	return binary.BigEndian.Uint32(data[offset : offset+4])
}

// ReadUint16LE reads uint16 in little-endian from byte slice
func ReadUint16LE(data []byte, offset int) uint16 {
	if offset+2 > len(data) {
		return 0
	}
	return binary.LittleEndian.Uint16(data[offset : offset+2])
}

// ReadUint32LE reads uint32 in little-endian from byte slice
func ReadUint32LE(data []byte, offset int) uint32 {
	if offset+4 > len(data) {
		return 0
	}
	return binary.LittleEndian.Uint32(data[offset : offset+4])
}

// SplitLines splits string by newlines and trims whitespace
func SplitLines(s string) []string {
	lines := strings.Split(s, "\n")
	result := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// CleanString removes non-printable characters
func CleanString(s string) string {
	var result strings.Builder
	for _, ch := range s {
		if ch >= 32 && ch <= 126 {
			result.WriteRune(ch)
		}
	}
	return result.String()
}
