package modules

import (
	"fmt"
	"strings"
	"time"

	"meow/grabber/pkg/enrichment/modules/helpers"
)

// CoAPModule implements the CoAP enrichment module
type CoAPModule struct {
	BaseModule
}

type CoAPResult struct {
	Protocol     string            `json:"protocol"`
	Version      string            `json:"version,omitempty"`
	Response     bool              `json:"response"`
	ResponseCode string            `json:"response_code,omitempty"`
	Resources    []string          `json:"resources,omitempty"`
	ResourceMap  map[string]string `json:"resource_map,omitempty"`
	ContentType  string            `json:"content_type,omitempty"`
	Error        string            `json:"error,omitempty"`
}

func init() {
	Register(&CoAPModule{
		BaseModule: NewBaseModule("coap", []string{}, true, 10*time.Second),
	})
}

func (m *CoAPModule) Scan(ip string, port int) (interface{}, error) {
	result := &CoAPResult{
		Protocol:    "coap",
		ResourceMap: make(map[string]string),
	}

	conn, err := helpers.DialUDP(ip, port, m.DefaultTimeout())
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	defer conn.Close()

	// CoAP GET request to /.well-known/core (resource discovery)
	coapRequest := []byte{
		0x40, 0x01, 0x00, 0x01, // Ver=1, Type=CON, Code=GET, MessageID=1
		0xbb, '.', 'w', 'e', 'l', 'l', '-', 'k', 'n', 'o', 'w', 'n',
		0x04, 'c', 'o', 'r', 'e',
	}

	_, err = conn.Write(coapRequest)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	response := make([]byte, 2048)
	n, err := conn.Read(response)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	if n < 4 {
		result.Error = "Response too short"
		return result, nil
	}

	// Parse CoAP header
	version := (response[0] >> 6) & 0x03
	tokenLen := response[0] & 0x0F
	code := response[1]

	result.Version = fmt.Sprintf("%d", version)
	result.Response = true

	// Parse response code (class.detail)
	codeClass := (code >> 5) & 0x07
	codeDetail := code & 0x1F
	result.ResponseCode = fmt.Sprintf("%d.%02d", codeClass, codeDetail)

	// Skip token and parse options/payload
	offset := 4 + int(tokenLen)
	if offset >= n {
		return result, nil
	}

	// Parse options (limit iterations to prevent infinite loops)
	const maxOptions = 100
	for i := 0; i < maxOptions && offset < n; i++ {
		if response[offset] == 0xFF {
			// Payload marker
			offset++
			break
		}

		// Option header
		optionDelta := (response[offset] >> 4) & 0x0F
		optionLength := response[offset] & 0x0F
		offset++

		// Extended option delta
		if optionDelta == 13 {
			if offset >= n {
				break
			}
			optionDelta = response[offset] + 13
			offset++
		} else if optionDelta == 14 {
			if offset+2 > n {
				break
			}
			optionDelta = response[offset]
			offset += 2
		}

		// Extended option length
		if optionLength == 13 {
			if offset >= n {
				break
			}
			optionLength = response[offset] + 13
			offset++
		} else if optionLength == 14 {
			if offset+2 > n {
				break
			}
			optionLength = response[offset]
			offset += 2
		}

		if offset+int(optionLength) > n {
			break
		}

		// Content-Format option (12)
		if optionDelta == 12 && optionLength > 0 {
			contentFormat := response[offset]
			result.ContentType = getCoapContentType(contentFormat)
		}

		offset += int(optionLength)
	}

	// Parse payload (resource links)
	if offset < n && codeClass == 2 {
		payload := string(response[offset:n])
		result.Resources = parseCoapResourceLinks(payload, result.ResourceMap)
	}

	return result, nil
}

// parseCoapResourceLinks parses CoRE Link Format
func parseCoapResourceLinks(payload string, resourceMap map[string]string) []string {
	var resources []string

	// Split by comma (each resource)
	links := strings.Split(payload, ",")
	for _, link := range links {
		link = strings.TrimSpace(link)
		if len(link) == 0 {
			continue
		}

		// Extract resource path between < and >
		if strings.HasPrefix(link, "<") {
			endIdx := strings.Index(link, ">")
			if endIdx > 0 {
				resource := link[1:endIdx]
				resources = append(resources, resource)

				// Extract resource attributes
				attrs := link[endIdx+1:]
				if len(attrs) > 0 {
					resourceMap[resource] = strings.TrimSpace(attrs)
				}
			}
		}
	}

	return resources
}

// getCoapContentType returns content type name for CoAP content format code
func getCoapContentType(code byte) string {
	switch code {
	case 0:
		return "text/plain"
	case 40:
		return "application/link-format"
	case 41:
		return "application/xml"
	case 42:
		return "application/octet-stream"
	case 47:
		return "application/exi"
	case 50:
		return "application/json"
	case 60:
		return "application/cbor"
	default:
		return fmt.Sprintf("unknown(%d)", code)
	}
}
