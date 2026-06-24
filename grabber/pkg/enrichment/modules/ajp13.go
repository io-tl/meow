package modules

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"time"

	"meow/grabber/pkg/enrichment/modules/helpers"
)

// AJP13Module implements the Apache JServ Protocol v1.3 enrichment module
type AJP13Module struct {
	BaseModule
}

// AJP13Result represents the enriched AJP13 data
type AJP13Result struct {
	Protocol   string            `json:"protocol"`
	Version    string            `json:"version,omitempty"`
	StatusCode int               `json:"status_code,omitempty"`
	StatusMsg  string            `json:"status_message,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	Server     string            `json:"server,omitempty"`
	PoweredBy  string            `json:"powered_by,omitempty"`
	Title      string            `json:"title,omitempty"`
	Body       string            `json:"body,omitempty"`
	Error      string            `json:"error,omitempty"`
}

func init() {
	Register(&AJP13Module{
		BaseModule: NewBaseModule(
			"ajp13",
			[]string{"ajp"},
			true, // Should enrich
			10*time.Second,
		),
	})
}

func (m *AJP13Module) Scan(ip string, port int) (interface{}, error) {
	return scanAJP13(ip, port, m.DefaultTimeout())
}

// scanAJP13 performs AJP13 enrichment: CPING/CPONG then GET / forward request
func scanAJP13(ip string, port int, timeout time.Duration) (*AJP13Result, error) {
	result := &AJP13Result{
		Protocol: "ajp13",
	}

	conn, err := helpers.DialTCP(ip, port, timeout)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	defer conn.Close()

	// Phase 1: CPING/CPONG to confirm AJP13
	cpingRequest := []byte{
		0x12, 0x34, // Magic
		0x00, 0x01, // Length: 1
		0x0a, // Type: CPING
	}

	if _, err = conn.Write(cpingRequest); err != nil {
		result.Error = err.Error()
		return result, err
	}

	response := make([]byte, 5)
	n, err := conn.Read(response)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	if n >= 5 && response[0] == 0x41 && response[1] == 0x42 {
		length := binary.BigEndian.Uint16(response[2:4])
		if length > 0 && response[4] == 0x09 { // CPONG
			result.Version = "1.3"
		}
	}

	if result.Version == "" {
		return result, nil
	}

	// Phase 2: open a fresh connection for the GET / forward request
	// (some AJP connectors close after CPONG)
	conn.Close()

	conn2, err := helpers.DialTCP(ip, port, timeout)
	if err != nil {
		return result, nil // not fatal, we already confirmed AJP
	}
	defer conn2.Close()

	forwardReq := buildAJPForwardRequest(ip, port)
	if _, err = conn2.Write(forwardReq); err != nil {
		return result, nil
	}

	parseAJPResponse(conn2, result)

	return result, nil
}

// buildAJPForwardRequest builds an AJP13 FORWARD_REQUEST packet for GET /
func buildAJPForwardRequest(ip string, port int) []byte {
	var body bytes.Buffer

	// Type: FORWARD_REQUEST
	body.WriteByte(0x02)
	// Method: GET = 2
	body.WriteByte(0x02)
	// Protocol
	ajpWriteString(&body, "HTTP/1.1")
	// Request URI
	ajpWriteString(&body, "/")
	// Remote Addr
	ajpWriteString(&body, "127.0.0.1")
	// Remote Host
	ajpWriteString(&body, "127.0.0.1")
	// Server Name
	ajpWriteString(&body, ip)
	// Server Port
	binary.Write(&body, binary.BigEndian, uint16(port))
	// Is SSL: false
	body.WriteByte(0x00)

	// 3 headers: Host, User-Agent, Connection
	binary.Write(&body, binary.BigEndian, uint16(3))

	// Host (0xA00B)
	binary.Write(&body, binary.BigEndian, uint16(0xA00B))
	hostVal := ip
	if port != 80 && port != 443 {
		hostVal = fmt.Sprintf("%s:%d", ip, port)
	}
	ajpWriteString(&body, hostVal)

	// User-Agent (0xA00E)
	binary.Write(&body, binary.BigEndian, uint16(0xA00E))
	ajpWriteString(&body, "Mozilla/5.0")

	// Connection (0xA006)
	binary.Write(&body, binary.BigEndian, uint16(0xA006))
	ajpWriteString(&body, "close")

	// Request terminator
	body.WriteByte(0xFF)

	// Wrap in AJP packet with magic + length prefix
	data := body.Bytes()
	packet := make([]byte, 4+len(data))
	packet[0] = 0x12
	packet[1] = 0x34
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(data)))
	copy(packet[4:], data)

	return packet
}

// ajpWriteString writes an AJP-encoded string: uint16 length + bytes + null terminator
func ajpWriteString(buf *bytes.Buffer, s string) {
	binary.Write(buf, binary.BigEndian, uint16(len(s)))
	buf.WriteString(s)
	buf.WriteByte(0x00)
}

// ajpReadString reads an AJP-encoded string from a bytes.Reader
func ajpReadString(r *bytes.Reader) (string, error) {
	var length uint16
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return "", err
	}
	if length == 0xFFFF { // null string marker
		return "", nil
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	r.ReadByte() // null terminator
	return string(buf), nil
}

// AJP13 response header codes
var ajpResponseHeaders = map[uint16]string{
	0xA001: "Content-Type",
	0xA002: "Content-Language",
	0xA003: "Content-Length",
	0xA004: "Date",
	0xA005: "Last-Modified",
	0xA006: "Location",
	0xA007: "Set-Cookie",
	0xA008: "Set-Cookie2",
	0xA009: "Servlet-Engine",
	0xA00A: "Status",
	0xA00B: "WWW-Authenticate",
}

const ajpMaxBodyCapture = 64 * 1024 // 64 KB max body for title extraction

// parseAJPResponse reads AJP response packets and populates the result
func parseAJPResponse(conn net.Conn, result *AJP13Result) {
	result.Headers = make(map[string]string)
	var bodyBuf bytes.Buffer

	for {
		// Read packet header: 'AB' magic (2) + length (2)
		header := make([]byte, 4)
		if _, err := io.ReadFull(conn, header); err != nil {
			break
		}
		if header[0] != 0x41 || header[1] != 0x42 {
			break
		}
		pktLen := binary.BigEndian.Uint16(header[2:4])
		if pktLen == 0 || pktLen > 16384 {
			break
		}

		data := make([]byte, pktLen)
		if _, err := io.ReadFull(conn, data); err != nil {
			break
		}

		if len(data) == 0 {
			break
		}

		pktType := data[0]
		payload := data[1:]

		switch pktType {
		case 0x04: // SEND_HEADERS
			ajpParseSendHeaders(payload, result)
		case 0x03: // SEND_BODY_CHUNK
			if len(payload) >= 2 {
				chunkLen := int(binary.BigEndian.Uint16(payload[0:2]))
				if chunkLen > 0 && chunkLen <= len(payload)-2 && bodyBuf.Len() < ajpMaxBodyCapture {
					remaining := ajpMaxBodyCapture - bodyBuf.Len()
					if chunkLen > remaining {
						chunkLen = remaining
					}
					bodyBuf.Write(payload[2 : 2+chunkLen])
				}
			}
		case 0x05: // END_RESPONSE
			goto done
		}
	}
done:

	// Extract page title from captured body
	if bodyBuf.Len() > 0 {
		body := bodyBuf.String()
		titleRe := regexp.MustCompile(`(?is)<title[^>]*>\s*(.*?)\s*</title>`)
		if m := titleRe.FindStringSubmatch(body); len(m) > 1 {
			title := strings.TrimSpace(m[1])
			if len(title) > 200 {
				title = title[:200]
			}
			result.Title = title
		}
	}

	// Store body
	if bodyBuf.Len() > 0 {
		result.Body = bodyBuf.String()
	}

	// Promote notable headers to top-level fields
	if s, ok := result.Headers["Server"]; ok {
		result.Server = s
	}
	if s, ok := result.Headers["X-Powered-By"]; ok {
		result.PoweredBy = s
	}
}

// ajpParseSendHeaders parses an AJP SEND_HEADERS packet payload
func ajpParseSendHeaders(data []byte, result *AJP13Result) {
	if len(data) < 4 {
		return
	}
	r := bytes.NewReader(data)

	// Status code (2 bytes)
	var statusCode uint16
	if err := binary.Read(r, binary.BigEndian, &statusCode); err != nil {
		return
	}
	result.StatusCode = int(statusCode)

	// Status message (AJP string)
	msg, err := ajpReadString(r)
	if err != nil {
		return
	}
	result.StatusMsg = msg

	// Number of headers
	var numHeaders uint16
	if err := binary.Read(r, binary.BigEndian, &numHeaders); err != nil {
		return
	}

	for i := 0; i < int(numHeaders); i++ {
		// Header name: 0xA0XX code or regular string
		var nameCode uint16
		if err := binary.Read(r, binary.BigEndian, &nameCode); err != nil {
			break
		}

		var name string
		if nameCode&0xFF00 == 0xA000 {
			// Standard header code
			name = ajpResponseHeaders[nameCode]
			if name == "" {
				name = fmt.Sprintf("X-AJP-0x%04X", nameCode)
			}
		} else {
			// nameCode is actually the string length
			nameBytes := make([]byte, nameCode)
			if _, err := io.ReadFull(r, nameBytes); err != nil {
				break
			}
			r.ReadByte() // null terminator
			name = string(nameBytes)
		}

		value, err := ajpReadString(r)
		if err != nil {
			break
		}

		result.Headers[name] = value
	}
}
