package modules

import (
	"bufio"
	"io"
	"strconv"
	"strings"
	"time"

	"meow/grabber/pkg/enrichment/modules/helpers"
)

// GitModule implements the Git protocol enrichment module
type GitModule struct {
	BaseModule
}

type GitResult struct {
	Protocol     string            `json:"protocol"`
	Version      string            `json:"version,omitempty"`
	Refs         []string          `json:"refs,omitempty"`
	Capabilities []string          `json:"capabilities,omitempty"`
	RefCount     int               `json:"ref_count"`
	HeadRef      string            `json:"head_ref,omitempty"`
	Branches     map[string]string `json:"branches,omitempty"`
	Tags         map[string]string `json:"tags,omitempty"`
	Error        string            `json:"error,omitempty"`
}

func init() {
	Register(&GitModule{
		BaseModule: NewBaseModule("git", []string{}, true, 10*time.Second),
	})
}

func (m *GitModule) Scan(ip string, port int) (interface{}, error) {
	result := &GitResult{
		Protocol: "git",
		Branches: make(map[string]string),
		Tags:     make(map[string]string),
	}

	conn, err := helpers.DialTCP(ip, port, m.DefaultTimeout())
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	defer conn.Close()
	reader := bufio.NewReader(conn)

	// Git upload-pack request
	if _, err := conn.Write([]byte("003egit-upload-pack /\x00host=scanner\x00")); err != nil {
		result.Error = err.Error()
		return result, err
	}

	// Read all refs using Git's pkt-line format
	const maxRefs = 1000
	for iteration := 0; iteration < maxRefs; iteration++ {
		// Read pkt-line length (4 hex digits)
		lengthBytes := make([]byte, 4)
		if _, err := io.ReadFull(reader, lengthBytes); err != nil {
			break
		}

		lengthStr := string(lengthBytes)
		if lengthStr == "0000" {
			// Flush packet - end of refs
			break
		}

		if len(lengthStr) != 4 {
			break
		}
		length, err := strconv.ParseInt(lengthStr, 16, 64)
		if err != nil || length < 4 {
			break
		}

		// Read the rest of the packet (length includes the 4-byte length prefix)
		dataLen := length - 4
		data := make([]byte, dataLen)
		if _, err := io.ReadFull(reader, data); err != nil {
			break
		}

		line := string(data)
		line = strings.TrimSpace(line)

		if !strings.Contains(line, " refs/") {
			continue
		}

		result.Version = "detected"
		result.Refs = append(result.Refs, line)
		result.RefCount++

		// Parse ref line: "hash refname\x00capabilities"
		parts := strings.SplitN(line, "\x00", 2)
		refLine := parts[0]

		// Extract capabilities from first ref
		if len(parts) > 1 && len(result.Capabilities) == 0 {
			capStr := parts[1]
			result.Capabilities = strings.Fields(capStr)
		}

		// Parse hash and ref name
		refParts := strings.Fields(refLine)
		if len(refParts) >= 2 {
			hash := refParts[0]
			refName := refParts[1]

			// Truncate hash to 8 chars if long enough
			shortHash := hash
			if len(hash) >= 8 {
				shortHash = hash[:8]
			}

			// Categorize refs
			if strings.HasPrefix(refName, "refs/heads/") {
				branchName := strings.TrimPrefix(refName, "refs/heads/")
				result.Branches[branchName] = shortHash
			} else if strings.HasPrefix(refName, "refs/tags/") {
				tagName := strings.TrimPrefix(refName, "refs/tags/")
				result.Tags[tagName] = shortHash
			} else if refName == "HEAD" {
				result.HeadRef = shortHash
			}
		}
	}

	return result, nil
}
