package modules

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"image"
	"image/draw"
	"image/png"
	"net"
	"reflect"
	"strings"
	"sync"
	"time"

	grdp "github.com/nakagami/grdp"

	"meow/grabber/pkg/enrichment/modules/helpers"
)

// RDPModule implements RDP enrichment module
type RDPModule struct {
	BaseModule
}

// RDPResult represents enriched RDP data
type RDPResult struct {
	Protocol            string   `json:"protocol"`
	SecurityProtocol    string   `json:"security_protocol,omitempty"`
	NetBIOSComputerName string   `json:"netbios_computer_name,omitempty"`
	DNSComputerName     string   `json:"dns_computer_name,omitempty"`
	CertificateCN       string   `json:"certificate_cn,omitempty"`
	Screenshot          string   `json:"screenshot,omitempty"`
	ScreenshotFormat    string   `json:"screenshot_format,omitempty"`
	TLS                 *TLSInfo `json:"tls,omitempty"`
	Error               string   `json:"error,omitempty"`
}

func init() {
	Register(&RDPModule{
		BaseModule: NewBaseModule(
			"rdp",
			[]string{"ms-wbt-server"},
			true, // Should enrich
			10*time.Second,
		),
	})
}

func (m *RDPModule) Scan(ip string, port int) (interface{}, error) {
	return scanRDP(ip, port, m.DefaultTimeout())
}

// scanRDP performs RDP enrichment with TLS certificate and NetBIOS extraction
func scanRDP(ip string, port int, timeout time.Duration) (*RDPResult, error) {
	// Try TLS handshake first to capture certificates and NetBIOS from certificate
	tlsResult, tlsErr := scanRDPWithTLS(ip, port, timeout)

	// If TLS failed, try NTLM authentication to get NetBIOS names
	ntlmResult, ntlmErr := scanRDPWithNTLM(ip, port, timeout)

	// Fallback to basic RDP detection
	basicResult, basicErr := scanRDPBasic(ip, port, timeout)

	result, err := basicResult, basicErr
	switch {
	case tlsErr == nil:
		result, err = tlsResult, nil
		if result.NetBIOSComputerName == "" && ntlmErr == nil {
			result.NetBIOSComputerName = ntlmResult.NetBIOSComputerName
			result.DNSComputerName = ntlmResult.DNSComputerName
		}
	case ntlmErr == nil && ntlmResult.NetBIOSComputerName != "":
		result, err = ntlmResult, nil
	case basicErr == nil:
		result, err = basicResult, nil
	}

	if result == nil {
		result = &RDPResult{Protocol: "rdp"}
	}

	if screenshot, screenshotErr := captureRDPScreenshot(ip, port, timeout); screenshotErr == nil && screenshot != "" {
		result.Screenshot = screenshot
		result.ScreenshotFormat = "png"
	}

	return result, err
}

// scanRDPWithTLS performs TLS handshake to capture RDP certificates and extract NetBIOS from certificate
func scanRDPWithTLS(ip string, port int, timeout time.Duration) (*RDPResult, error) {
	result := &RDPResult{
		Protocol: "rdp",
	}

	// Step 1: Basic TCP connection
	conn, err := helpers.DialTCP(ip, port, timeout)
	if err != nil {
		result.Error = fmt.Sprintf("TCP connection failed: %v", err)
		return result, err
	}
	defer conn.Close()

	// Step 2: Send RDP connection request with TLS protocol negotiation
	rdpNegReq := []byte{
		0x03, 0x00, // TPKT Header: version
		0x00, 0x13, // TPKT Header: length (19 bytes)
		0x0e,       // X.224 length
		0xe0,       // X.224 type: Connection Request
		0x00, 0x00, // dst-ref
		0x00, 0x00, // src-ref
		0x00,       // class
		0x01,       // Type: TYPE_RDP_NEG_REQ
		0x00,       // Flags
		0x08, 0x00, // Length: 8
		0x0F, 0x00, 0x00, 0x00, // requestedProtocols: PROTOCOL_RDP|SSL|HYBRID|RDSTLS = 0x0F
	}

	// Send request
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		result.Error = fmt.Sprintf("set deadline failed: %v", err)
		return result, err
	}
	if _, err := conn.Write(rdpNegReq); err != nil {
		result.Error = fmt.Sprintf("write RDP neg request failed: %v", err)
		return result, err
	}

	// Read response
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		result.Error = fmt.Sprintf("read RDP neg response failed: %v", err)
		return result, err
	}
	response := buf[:n]

	// Check if TLS was accepted
	if len(response) < 19 {
		result.Error = fmt.Sprintf("response too short: %d bytes", len(response))
		return result, fmt.Errorf("response too short: %d bytes", len(response))
	}

	// Parse RDP negotiation response
	negType := response[11]
	if negType == 0x03 { // TYPE_RDP_NEG_FAILURE
		result.Error = "RDP server rejected TLS negotiation (NEG_FAILURE)"
		return result, fmt.Errorf("RDP server rejected TLS negotiation")
	}
	if negType != 0x02 { // Not TYPE_RDP_NEG_RSP
		result.Error = fmt.Sprintf("unexpected RDP negotiation response type: 0x%02x", negType)
		return result, fmt.Errorf("unexpected RDP negotiation response type: 0x%02x", negType)
	}

	// Check selected protocol
	if len(response) >= 19 {
		selectedProtocol := uint32(response[15]) | uint32(response[16])<<8 |
			uint32(response[17])<<16 | uint32(response[18])<<24

		// Accept any TLS-based protocol
		isTLSBased := (selectedProtocol & 0x0F) != 0
		if !isTLSBased {
			result.Error = fmt.Sprintf("RDP server selected non-TLS protocol: 0x%08x", selectedProtocol)
			return result, fmt.Errorf("RDP server selected non-TLS protocol: 0x%08x", selectedProtocol)
		}
	}

	// Step 3: Upgrade to TLS
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         ip,
	}

	tlsConn := tls.Client(conn, tlsConfig)
	if err := tlsConn.SetDeadline(time.Now().Add(timeout)); err != nil {
		result.Error = fmt.Sprintf("set TLS deadline failed: %v", err)
		return result, err
	}

	// Perform TLS handshake
	if err := tlsConn.Handshake(); err != nil {
		result.Error = fmt.Sprintf("TLS handshake failed: %v", err)
		return result, err
	}

	// Extract TLS information using shared converter
	state := tlsConn.ConnectionState()
	result.TLS = TLSInfoFromConnectionState(&state)
	result.SecurityProtocol = "TLS"

	// Extract CN and NetBIOS from first (leaf) certificate
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		if cert.Subject.CommonName != "" {
			result.CertificateCN = cert.Subject.CommonName
			if netbiosName := extractNetBIOSFromName(cert.Subject.CommonName); netbiosName != "" {
				result.NetBIOSComputerName = netbiosName
			}
		}
		if result.NetBIOSComputerName == "" {
			for _, dnsName := range cert.DNSNames {
				if netbiosName := extractNetBIOSFromName(dnsName); netbiosName != "" {
					result.NetBIOSComputerName = netbiosName
					break
				}
			}
		}
	}

	return result, nil
}

// scanRDPWithNTLM performs NTLM authentication detection to extract NetBIOS names
func scanRDPWithNTLM(ip string, port int, timeout time.Duration) (*RDPResult, error) {
	result := &RDPResult{
		Protocol: "rdp",
	}

	conn, err := helpers.DialTCP(ip, port, timeout)
	if err != nil {
		result.Error = fmt.Sprintf("TCP connection failed: %v", err)
		return result, err
	}
	defer conn.Close()

	// CredSSP protocol - NTLM authentication
	negotiatePacket := []byte{
		0x30, 0x37, 0xA0, 0x03, 0x02, 0x01, 0x60, 0xA1, 0x30, 0x30, 0x2E, 0x30, 0x2C, 0xA0, 0x2A, 0x04, 0x28,
		// NTLMSSP Signature
		'N', 'T', 'L', 'M', 'S', 'S', 'P', 0x00,
		// Message Type (Negotiate)
		0x01, 0x00, 0x00, 0x00,
		// Negotiate Flags
		0xF7, 0xBA, 0xDB, 0xE2,
		// Domain Name Fields (empty)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// Workstation Fields (empty)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// Version
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	response, err := sendRecv(conn, negotiatePacket, timeout)
	if err != nil {
		result.Error = fmt.Sprintf("NTLM negotiate failed: %v", err)
		return result, err
	}

	result.SecurityProtocol = "NTLM"

	// NTLM Challenge structure
	type NTLMChallenge struct {
		Signature              [8]byte
		MessageType            uint32
		TargetNameLen          uint16
		TargetNameMaxLen       uint16
		TargetNameBufferOffset uint32
		NegotiateFlags         uint32
		ServerChallenge        uint64
		Reserved               uint64
		TargetInfoLen          uint16
		TargetInfoMaxLen       uint16
		TargetInfoBufferOffset uint32
		Version                [8]byte
	}

	challengeLen := 56
	challengeStartOffset := bytes.Index(response, []byte{'N', 'T', 'L', 'M', 'S', 'S', 'P', 0})
	if challengeStartOffset == -1 {
		result.Error = "NTLM signature not found in response"
		return result, fmt.Errorf("NTLM signature not found")
	}

	if len(response) < challengeStartOffset+challengeLen {
		result.Error = "NTLM challenge response too short"
		return result, fmt.Errorf("NTLM challenge response too short")
	}

	var responseData NTLMChallenge
	response = response[challengeStartOffset:]
	responseBuf := bytes.NewBuffer(response)
	err = binary.Read(responseBuf, binary.LittleEndian, &responseData)
	if err != nil {
		result.Error = fmt.Sprintf("Failed to parse NTLM challenge: %v", err)
		return result, err
	}

	// Validate NTLM challenge response
	if responseData.MessageType != 0x00000002 ||
		responseData.Reserved != 0 ||
		!reflect.DeepEqual(responseData.Version[4:], []byte{0, 0, 0, 0xF}) {
		result.Error = "Invalid NTLM challenge response"
		return result, fmt.Errorf("Invalid NTLM challenge response")
	}

	// Parse TargetInfo (AV_PAIR list) for NetBIOS names
	avIDMap := map[uint16]string{
		1: "NetBIOSComputerName",
		2: "NetBIOSDomainName",
		3: "DNSComputerName",
		4: "DNSDomainName",
		5: "ForestName",
	}

	type AVPair struct {
		AvID  uint16
		AvLen uint16
	}

	targetInfoLen := int(responseData.TargetInfoLen)
	if targetInfoLen > 0 {
		startIdx := int(responseData.TargetInfoBufferOffset)
		if startIdx+targetInfoLen > len(response) {
			result.Error = "Invalid TargetInfoLen value"
			return result, fmt.Errorf("Invalid TargetInfoLen value")
		}

		currIdx := startIdx
		for currIdx+4 <= startIdx+targetInfoLen {
			var avPair AVPair
			avPairBuf := bytes.NewBuffer(response[currIdx : currIdx+4])
			err = binary.Read(avPairBuf, binary.LittleEndian, &avPair)
			if err != nil {
				break
			}

			if avPair.AvID == 0 {
				break
			}

			if field, exists := avIDMap[avPair.AvID]; exists {
				valueStart := currIdx + 4
				valueEnd := valueStart + int(avPair.AvLen)
				if valueEnd <= len(response) {
					value := strings.ReplaceAll(string(response[valueStart:valueEnd]), "\x00", "")
					switch field {
					case "NetBIOSComputerName":
						result.NetBIOSComputerName = value
					case "DNSComputerName":
						result.DNSComputerName = value
					}
				}
			}

			currIdx += 4 + int(avPair.AvLen)
		}
	}

	return result, nil
}

// scanRDPBasic performs basic RDP detection (fallback method)
func scanRDPBasic(ip string, port int, timeout time.Duration) (*RDPResult, error) {
	result := &RDPResult{
		Protocol: "rdp",
	}

	conn, err := helpers.DialTCP(ip, port, timeout)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	defer conn.Close()

	// Build X.224 Connection Request
	connectionRequest := buildRDPConnectionRequest()

	_, err = conn.Write(connectionRequest)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	// Read response
	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	if n > 11 {
		// Parse X.224 Connection Confirm
		// TPKT header (4 bytes) + X.224 Connection Confirm
		tpktLength := binary.BigEndian.Uint16(response[2:4])
		if tpktLength > 0 && n >= int(tpktLength) {
			// Check for RDP negotiation response
			if n > 19 {
				// Flags at offset 19
				flags := response[19]
				if flags&0x01 != 0 {
					result.SecurityProtocol = "TLS"
				} else if flags&0x02 != 0 {
					result.SecurityProtocol = "CredSSP"
				} else {
					result.SecurityProtocol = "Standard RDP"
				}
			}
		}
	}

	return result, nil
}

// sendRecv sends data and receives response
func sendRecv(conn net.Conn, data []byte, timeout time.Duration) ([]byte, error) {
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}

	if _, err := conn.Write(data); err != nil {
		return nil, err
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}

	return buf[:n], nil
}

// extractNetBIOSFromName extracts NetBIOS name from certificate CN or DNS name
func extractNetBIOSFromName(name string) string {
	if name == "" {
		return ""
	}

	// Remove any leading *. for wildcard certificates
	name = strings.TrimPrefix(name, "*.")

	// Split by dots and take the first part
	parts := strings.Split(name, ".")
	if len(parts) == 0 {
		return ""
	}

	candidate := parts[0]

	// Check if it looks like a NetBIOS name
	// NetBIOS names are typically:
	// - All uppercase
	// - 15 characters or less
	// - Contain letters, numbers, and hyphens
	if len(candidate) > 15 {
		return ""
	}

	// Check if it's all uppercase (common for NetBIOS)
	if strings.ToUpper(candidate) == candidate && !strings.Contains(candidate, " ") {
		return candidate
	}

	// Also accept common patterns like WIN-ABC123 or DESKTOP-XYZ
	if strings.HasPrefix(strings.ToUpper(candidate), "WIN-") ||
		strings.HasPrefix(strings.ToUpper(candidate), "DESKTOP-") ||
		strings.HasPrefix(strings.ToUpper(candidate), "PC-") ||
		strings.HasPrefix(strings.ToUpper(candidate), "SRV-") ||
		strings.HasPrefix(strings.ToUpper(candidate), "SERVER-") {
		return candidate
	}

	return ""
}

// EncodeCertToPEM encodes a certificate DER in PEM format
func EncodeCertToPEM(derBytes []byte) string {
	encoded := "-----BEGIN CERTIFICATE-----\n"
	b64 := base64Encode(derBytes)
	for i := 0; i < len(b64); i += 64 {
		end := i + 64
		if end > len(b64) {
			end = len(b64)
		}
		encoded += b64[i:end] + "\n"
	}
	encoded += "-----END CERTIFICATE-----"
	return encoded
}

// base64Encode encodes data in base64 (simple implementation)
func base64Encode(data []byte) string {
	const base64Table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var result strings.Builder
	n := len(data)

	for i := 0; i < n; i += 3 {
		b1 := data[i]
		var b2, b3 byte
		if i+1 < n {
			b2 = data[i+1]
		}
		if i+2 < n {
			b3 = data[i+2]
		}

		result.WriteByte(base64Table[b1>>2])
		result.WriteByte(base64Table[((b1&0x03)<<4)|((b2&0xf0)>>4)])

		if i+1 < n {
			result.WriteByte(base64Table[((b2&0x0f)<<2)|((b3&0xc0)>>6)])
		} else {
			result.WriteByte('=')
		}

		if i+2 < n {
			result.WriteByte(base64Table[b3&0x3f])
		} else {
			result.WriteByte('=')
		}
	}

	return result.String()
}

func captureRDPScreenshot(ip string, port int, timeout time.Duration) (string, error) {
	captureTimeout := min(timeout, 5*time.Second)
	collector := newRDPScreenshotCollector(1024, 768)
	bitmapCh := make(chan []grdp.Bitmap, 8)
	errCh := make(chan error, 2)
	closeCh := make(chan struct{}, 1)

	client := grdp.NewRdpClient(fmt.Sprintf("%s:%d", ip, port), 1024, 768)
	if err := client.Login("", "", ""); err != nil {
		client.Close()
		return "", err
	}
	defer client.Close()

	client.OnBitmap(func(bitmaps []grdp.Bitmap) {
		select {
		case bitmapCh <- bitmaps:
		default:
		}
	}).OnError(func(e error) {
		select {
		case errCh <- e:
		default:
		}
	}).OnClose(func() {
		select {
		case closeCh <- struct{}{}:
		default:
		}
	})

	waitTimer := time.NewTimer(captureTimeout)
	defer waitTimer.Stop()

	idleDelay := min(750*time.Millisecond, captureTimeout)
	idleTimer := time.NewTimer(idleDelay)
	if !idleTimer.Stop() {
		<-idleTimer.C
	}

	gotBitmap := false
	for {
		select {
		case bitmaps := <-bitmapCh:
			collector.Paint(bitmaps)
			if collector.HasPixels() {
				gotBitmap = true
				if !idleTimer.Stop() {
					select {
					case <-idleTimer.C:
					default:
					}
				}
				idleTimer.Reset(idleDelay)
			}
		case <-idleTimer.C:
			if gotBitmap {
				return collector.PNGDataURL()
			}
		case err := <-errCh:
			if gotBitmap {
				return collector.PNGDataURL()
			}
			return "", err
		case <-closeCh:
			if gotBitmap {
				return collector.PNGDataURL()
			}
			return "", fmt.Errorf("rdp session closed before any bitmap")
		case <-waitTimer.C:
			if gotBitmap {
				return collector.PNGDataURL()
			}
			return "", fmt.Errorf("rdp screenshot timeout")
		}
	}
}

type rdpScreenshotCollector struct {
	mu      sync.Mutex
	img     *image.RGBA
	painted bool
}

func newRDPScreenshotCollector(width, height int) *rdpScreenshotCollector {
	return &rdpScreenshotCollector{
		img: image.NewRGBA(image.Rect(0, 0, width, height)),
	}
}

func (c *rdpScreenshotCollector) HasPixels() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.painted
}

func (c *rdpScreenshotCollector) Paint(bitmaps []grdp.Bitmap) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, bitmap := range bitmaps {
		if bitmap.Width == 0 || bitmap.Height == 0 {
			continue
		}

		rgba := bitmap.RGBA()

		dest := image.Rect(
			bitmap.DestLeft,
			bitmap.DestTop,
			bitmap.DestLeft+bitmap.Width,
			bitmap.DestTop+bitmap.Height,
		)
		draw.Draw(c.img, dest, rgba, image.Point{}, draw.Src)
		c.painted = true
	}
}

func (c *rdpScreenshotCollector) PNGDataURL() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.painted {
		return "", fmt.Errorf("no bitmap captured")
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, c.img); err != nil {
		return "", err
	}

	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

// buildRDPConnectionRequest builds an X.224 Connection Request with RDP negotiation
func buildRDPConnectionRequest() []byte {
	// TPKT Header (4 bytes)
	tpkt := []byte{
		0x03,       // Version
		0x00,       // Reserved
		0x00, 0x2b, // Length (43 bytes)
	}

	// X.224 Connection Request (7 bytes)
	x224 := []byte{
		0x26,       // Length
		0xe0,       // Type: Connection Request
		0x00, 0x00, // Destination reference
		0x00, 0x00, // Source reference
		0x00, // Class and options
	}

	// RDP Negotiation Request (8 bytes)
	rdpNegReq := []byte{
		0x01,       // Type: RDP_NEG_REQ
		0x00,       // Flags
		0x08, 0x00, // Length
		0x01, 0x00, 0x00, 0x00, // Requested protocols: TLS
	}

	// Cookie
	cookie := []byte("Cookie: mstshash=probe\r\n")

	packet := append(tpkt, x224...)
	packet = append(packet, cookie...)
	packet = append(packet, rdpNegReq...)

	// Update length
	totalLen := len(packet)
	packet[2] = byte(totalLen >> 8)
	packet[3] = byte(totalLen)
	packet[5] = byte(totalLen - 5) // X.224 length

	return packet
}
