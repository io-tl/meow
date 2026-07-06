package modules

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
	"unicode/utf16"

	"meow/grabber/pkg/enrichment/modules/helpers"

	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/dcerpc"
	"github.com/jfjallid/go-smb/smb/dcerpc/mssrvs"
	"github.com/jfjallid/go-smb/spnego"
)

// SMBModule implements the SMB enrichment module
type SMBModule struct {
	BaseModule
}

// SMBResult contains SMB detection results
type SMBResult struct {
	Protocol        string           `json:"protocol"`
	IsSMB           bool             `json:"is_smb"`
	SMBVersion      *SMBVersionInfo  `json:"smb_version,omitempty"`
	TargetName      string           `json:"target_name,omitempty"`  // Domain or machine name
	NetBIOSName     string           `json:"netbios_name,omitempty"` // NetBIOS machine name
	DomainName      string           `json:"domain_name,omitempty"`  // DNS domain name
	OSVersion       string           `json:"os_version,omitempty"`   // Operating system version
	SMBCapabilities *SMBCapabilities `json:"smb_capabilities,omitempty"`
	SecurityMode    *SecurityMode    `json:"security_mode,omitempty"`
	SystemTime      string           `json:"system_time,omitempty"`       // Formatted date
	ServerStartTime string           `json:"server_start_time,omitempty"` // Formatted date
	HasNTLM         bool             `json:"has_ntlm"`
	Shares          []ShareInfo      `json:"shares,omitempty"`        // List of shares
	SharesMethod    string           `json:"shares_method,omitempty"` // Method used to enumerate shares
	NegotiationLog  *NegotiationLog  `json:"negotiation_log,omitempty"`
	SessionSetupLog *SessionSetupLog `json:"session_setup_log,omitempty"`
	Error           string           `json:"error,omitempty"`
}

// ShareInfo contains information about a SMB share
type ShareInfo struct {
	Name    string `json:"name"`
	Comment string `json:"comment,omitempty"`
	Type    string `json:"type"`
}

// SecurityMode describes SMB security settings
type SecurityMode struct {
	MessageSigningEnabled  bool   `json:"message_signing_enabled"`
	MessageSigningRequired bool   `json:"message_signing_required"`
	Description            string `json:"description"`
}

type SMBVersionInfo struct {
	Major         uint16 `json:"major"`
	Minor         uint16 `json:"minor"`
	Revision      uint16 `json:"revision"`
	VersionString string `json:"version_string"`
}

type SMBCapabilities struct {
	SMBDFSSupport         bool `json:"smb_dfs_support"`
	SMBLeasingSupport     bool `json:"smb_leasing_support"`
	SMBMulticreditSupport bool `json:"smb_multicredit_support"`
	SMBEncryptionSupport  bool `json:"smb_encryption_support,omitempty"`
	SMBLargeMTU           bool `json:"smb_large_mtu,omitempty"`
}

type NegotiationLog struct {
	ProtocolID          []byte   `json:"protocol_id"`
	Status              uint32   `json:"status"`
	Command             uint16   `json:"command"`
	Credits             uint16   `json:"credits"`
	Flags               uint32   `json:"flags"`
	SecurityMode        uint16   `json:"security_mode"`
	DialectRevision     uint16   `json:"dialect_revision"`
	ServerGUID          []byte   `json:"server_guid"`
	Capabilities        uint32   `json:"capabilities"`
	SystemTime          uint64   `json:"system_time"`
	ServerStartTime     uint64   `json:"server_start_time"`
	AuthenticationTypes []string `json:"authentication_types,omitempty"`
}

type SessionSetupLog struct {
	ProtocolID     []byte `json:"protocol_id"`
	Status         uint32 `json:"status"`
	Command        uint16 `json:"command"`
	Credits        uint16 `json:"credits"`
	Flags          uint32 `json:"flags"`
	SetupFlags     uint16 `json:"setup_flags"`
	TargetName     string `json:"target_name,omitempty"`
	NegotiateFlags uint32 `json:"negotiate_flags,omitempty"`
}

const (
	// SMB2 Protocol ID
	SMB2ProtocolID = "\xfeSMB"

	// SMB2 Commands
	SMB2Negotiate    = 0x0000
	SMB2SessionSetup = 0x0001

	// SMB2 Capabilities
	SMB2GlobalCapDFS         = 0x00000001
	SMB2GlobalCapLeasing     = 0x00000002
	SMB2GlobalCapLargeMTU    = 0x00000004
	SMB2GlobalCapMultiCredit = 0x00000008
	SMB2GlobalCapEncryption  = 0x00000040
)

func init() {
	Register(&SMBModule{
		BaseModule: NewBaseModule(
			"smb",
			// netbios-ssn is the service name nmap-service-probes assigns to
			// SMB on 139/445; it must route to this module, not to the nbtstat
			// name-service module (see netbios.go).
			[]string{"microsoft-ds", "netbios-ssn"},
			true, // Should enrich
			15*time.Second,
		),
	})
}

func (m *SMBModule) Scan(ip string, port int) (interface{}, error) {
	return scanSMB(ip, port, m.DefaultTimeout())
}

// ScanWithSNI - SMB doesn't use SNI
func (m *SMBModule) ScanWithSNI(ip string, port int, domain string) (interface{}, error) {
	return m.Scan(ip, port)
}

// readSMBMessage reads a full NetBIOS-framed SMB message from the connection.
// The NetBIOS header is 4 bytes: type (1) + length (3).
// Returns the complete message including the 4-byte header.
func readSMBMessage(conn net.Conn) ([]byte, error) {
	// Read the 4-byte NetBIOS header
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return nil, fmt.Errorf("failed to read NetBIOS header: %w", err)
	}

	// Length is 3 bytes big-endian (max ~16MB)
	length := int(hdr[1])<<16 | int(hdr[2])<<8 | int(hdr[3])
	if length == 0 {
		return hdr, nil
	}
	if length > 1<<20 { // sanity cap at 1MB
		return nil, fmt.Errorf("SMB message too large: %d bytes", length)
	}

	// Read the payload
	payload := make([]byte, length)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, fmt.Errorf("failed to read SMB payload: %w", err)
	}

	return append(hdr, payload...), nil
}

// setupNetBIOSSession establishes a NetBIOS session on port 139.
// Must be called before sending SMB traffic on port 139.
func setupNetBIOSSession(conn net.Conn) error {
	sessionRequest := buildNetBIOSSessionRequest()
	if _, err := conn.Write(sessionRequest); err != nil {
		return fmt.Errorf("failed to send NetBIOS session request: %w", err)
	}

	// Read the 4-byte response header
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return fmt.Errorf("failed to read NetBIOS session response: %w", err)
	}

	msgType := hdr[0]
	switch msgType {
	case 0x82:
		// Positive session response - success
		return nil
	case 0x83:
		// Negative session response
		return fmt.Errorf("NetBIOS session rejected (0x83)")
	case 0x84:
		// Retarget
		return fmt.Errorf("NetBIOS session retarget (0x84)")
	default:
		return fmt.Errorf("unexpected NetBIOS response type: 0x%02x", msgType)
	}
}

// scanSMB performs SMB enrichment
func scanSMB(host string, port int, timeout time.Duration) (*SMBResult, error) {
	// Connect using helper
	conn, err := helpers.DialTCP(host, port, timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}
	defer conn.Close()

	// Port 139 requires NetBIOS session setup before SMB traffic
	if port == 139 {
		if err := setupNetBIOSSession(conn); err != nil {
			return nil, fmt.Errorf("NetBIOS session setup failed: %w", err)
		}
	}

	// Send SMB2 NEGOTIATE
	negotiateReq := buildSMB2NegotiateRequest()
	if _, err := conn.Write(negotiateReq); err != nil {
		return nil, fmt.Errorf("failed to send negotiate: %w", err)
	}

	// Read full response using NetBIOS framing
	buf, err := readSMBMessage(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Parse SMB2 response
	result, err := parseSMB2NegotiateResponse(buf)
	if err != nil {
		return nil, err
	}

	// Try NTLM challenge via SESSION_SETUP on the same connection
	if err := extractNTLMInfo(conn, result); err == nil {
		result.HasNTLM = true
	}

	// If NetBIOS name is still invalid/missing, try extracting from server GUID
	if isInvalidName(result.NetBIOSName) {
		if result.NegotiationLog != nil && len(result.NegotiationLog.ServerGUID) > 0 {
			if guidName := extractNameFromGUID(result.NegotiationLog.ServerGUID); guidName != "" && !isInvalidName(guidName) {
				result.NetBIOSName = guidName
			}
		}
	}

	// Validate and clean TargetName
	if isInvalidName(result.TargetName) {
		result.TargetName = ""
		// Use NetBIOS name as fallback if we have one
		if !isInvalidName(result.NetBIOSName) {
			result.TargetName = result.NetBIOSName
		}
	}

	// Try to enumerate shares (anonymous access)
	if shares, method, err := tryEnumerateShares(host, port); err == nil && len(shares) > 0 {
		result.Shares = shares
		result.SharesMethod = method
	}

	return result, nil
}

// buildSMB2NegotiateRequest builds an SMB2 NEGOTIATE request
func buildSMB2NegotiateRequest() []byte {
	// NetBIOS Session Service header (4 bytes)
	netbios := make([]byte, 4)
	// Type: Session message (0x00), Length will be set later

	// SMB2 Header (64 bytes)
	header := make([]byte, 64)
	copy(header[0:4], []byte(SMB2ProtocolID))                   // ProtocolId
	binary.LittleEndian.PutUint16(header[4:6], 64)              // StructureSize
	binary.LittleEndian.PutUint16(header[6:8], 0)               // CreditCharge
	binary.LittleEndian.PutUint32(header[8:12], 0)              // Status
	binary.LittleEndian.PutUint16(header[12:14], SMB2Negotiate) // Command
	binary.LittleEndian.PutUint16(header[14:16], 1)             // CreditRequest
	binary.LittleEndian.PutUint32(header[16:20], 0)             // Flags
	binary.LittleEndian.PutUint32(header[20:24], 0)             // NextCommand
	binary.LittleEndian.PutUint64(header[24:32], 0)             // MessageId
	binary.LittleEndian.PutUint32(header[32:36], 0)             // Reserved
	binary.LittleEndian.PutUint32(header[36:40], 0)             // TreeId
	binary.LittleEndian.PutUint64(header[40:48], 0)             // SessionId
	// Signature (16 bytes) at offset 48

	// SMB2 NEGOTIATE Request (36 bytes)
	negotiate := make([]byte, 36)
	binary.LittleEndian.PutUint16(negotiate[0:2], 36)    // StructureSize
	binary.LittleEndian.PutUint16(negotiate[2:4], 4)     // DialectCount
	binary.LittleEndian.PutUint16(negotiate[4:6], 1)     // SecurityMode (signing enabled)
	binary.LittleEndian.PutUint16(negotiate[6:8], 0)     // Reserved
	binary.LittleEndian.PutUint32(negotiate[8:12], 0x7F) // Capabilities
	// ClientGUID (16 bytes) at offset 12
	for i := 12; i < 28; i++ {
		negotiate[i] = 0
	}
	binary.LittleEndian.PutUint32(negotiate[28:32], 0) // NegotiateContextOffset
	binary.LittleEndian.PutUint16(negotiate[32:34], 0) // NegotiateContextCount
	binary.LittleEndian.PutUint16(negotiate[34:36], 0) // Reserved2

	// Dialects (8 bytes - 4 dialects x 2 bytes)
	// Note: SMB 3.1.1 (0x0311) is excluded as it requires negotiate contexts
	dialects := make([]byte, 8)
	binary.LittleEndian.PutUint16(dialects[0:2], 0x0202) // SMB 2.0.2
	binary.LittleEndian.PutUint16(dialects[2:4], 0x0210) // SMB 2.1
	binary.LittleEndian.PutUint16(dialects[4:6], 0x0300) // SMB 3.0
	binary.LittleEndian.PutUint16(dialects[6:8], 0x0302) // SMB 3.0.2

	// Combine all parts
	payload := append(header, negotiate...)
	payload = append(payload, dialects...)

	// Set NetBIOS length (total length - 4 bytes)
	length := len(payload)
	netbios[1] = byte(length >> 16)
	netbios[2] = byte(length >> 8)
	netbios[3] = byte(length)

	return append(netbios, payload...)
}

// parseSMB2NegotiateResponse parses the SMB2 NEGOTIATE response
func parseSMB2NegotiateResponse(data []byte) (*SMBResult, error) {
	result := &SMBResult{
		Protocol: "smb",
		IsSMB:    true,
		HasNTLM:  false,
	}

	// Skip NetBIOS header (4 bytes)
	if len(data) < 4 {
		return nil, fmt.Errorf("response too short")
	}
	data = data[4:]

	// Verify SMB2 header
	if len(data) < 64 {
		return nil, fmt.Errorf("SMB2 header too short")
	}

	if string(data[0:4]) != SMB2ProtocolID {
		return nil, fmt.Errorf("invalid protocol ID")
	}

	// Parse SMB2 header
	status := binary.LittleEndian.Uint32(data[8:12])
	command := binary.LittleEndian.Uint16(data[12:14])
	credits := binary.LittleEndian.Uint16(data[14:16])
	flags := binary.LittleEndian.Uint32(data[16:20])

	if command != SMB2Negotiate {
		return nil, fmt.Errorf("unexpected command: %d", command)
	}

	// Parse SMB2 NEGOTIATE Response
	if len(data) < 70 {
		return nil, fmt.Errorf("negotiate response too short")
	}

	securityMode := binary.LittleEndian.Uint16(data[66:68])
	dialectRevision := binary.LittleEndian.Uint16(data[68:70])

	// Check if dialect is 0x0000 or 0xFFFF (error or not supported)
	if dialectRevision == 0x0000 || dialectRevision == 0xFFFF {
		// Server might not support SMB2/3, or there's an error
		// Check status code
		if status != 0 {
			return nil, fmt.Errorf("SMB negotiation failed with status 0x%08x", status)
		}
	}

	// Determine SMB version from dialect
	result.SMBVersion = &SMBVersionInfo{}
	switch dialectRevision {
	case 0x0202:
		result.SMBVersion.Major = 2
		result.SMBVersion.Minor = 0
		result.SMBVersion.Revision = 2
		result.SMBVersion.VersionString = "SMB 2.0.2"
	case 0x0210:
		result.SMBVersion.Major = 2
		result.SMBVersion.Minor = 1
		result.SMBVersion.Revision = 0
		result.SMBVersion.VersionString = "SMB 2.1"
	case 0x0300:
		result.SMBVersion.Major = 3
		result.SMBVersion.Minor = 0
		result.SMBVersion.Revision = 0
		result.SMBVersion.VersionString = "SMB 3.0"
	case 0x0302:
		result.SMBVersion.Major = 3
		result.SMBVersion.Minor = 0
		result.SMBVersion.Revision = 2
		result.SMBVersion.VersionString = "SMB 3.0.2"
	case 0x0311:
		result.SMBVersion.Major = 3
		result.SMBVersion.Minor = 1
		result.SMBVersion.Revision = 1
		result.SMBVersion.VersionString = "SMB 3.1.1"
	default:
		result.SMBVersion.VersionString = fmt.Sprintf("SMB (dialect 0x%04x)", dialectRevision)
	}

	if len(data) < 88 {
		return result, nil
	}

	// ServerGUID (16 bytes at offset 72)
	serverGUID := make([]byte, 16)
	copy(serverGUID, data[72:88])

	// Extract NetBIOS name from server GUID (often contains hostname in first bytes)
	// The GUID often starts with the machine name followed by null bytes
	// Use this as the primary source for Samba servers
	guidName := extractNameFromGUID(serverGUID)
	if guidName != "" {
		result.NetBIOSName = guidName
	}

	capabilities := binary.LittleEndian.Uint32(data[88:92])

	// Parse capabilities
	result.SMBCapabilities = &SMBCapabilities{
		SMBDFSSupport:         (capabilities & SMB2GlobalCapDFS) != 0,
		SMBLeasingSupport:     (capabilities & SMB2GlobalCapLeasing) != 0,
		SMBMulticreditSupport: (capabilities & SMB2GlobalCapMultiCredit) != 0,
		SMBEncryptionSupport:  (capabilities & SMB2GlobalCapEncryption) != 0,
		SMBLargeMTU:           (capabilities & SMB2GlobalCapLargeMTU) != 0,
	}

	if len(data) < 108 {
		return result, nil
	}

	systemTime := binary.LittleEndian.Uint64(data[92:100])
	serverStartTime := binary.LittleEndian.Uint64(data[100:108])

	// Parse security mode
	result.SecurityMode = parseSecurityMode(securityMode)

	// Format dates
	result.SystemTime = formatFileTime(systemTime)
	if serverStartTime > 0 {
		result.ServerStartTime = formatFileTime(serverStartTime)
	} else {
		result.ServerStartTime = "N/A"
	}

	// Create negotiation log
	result.NegotiationLog = &NegotiationLog{
		ProtocolID:      []byte(SMB2ProtocolID),
		Status:          status,
		Command:         command,
		Credits:         credits,
		Flags:           flags,
		SecurityMode:    securityMode,
		DialectRevision: dialectRevision,
		ServerGUID:      serverGUID,
		Capabilities:    capabilities,
		SystemTime:      systemTime,
		ServerStartTime: serverStartTime,
	}

	// Parse security buffer to extract NTLM info
	if len(data) >= 110 {
		securityBufferOffset := binary.LittleEndian.Uint16(data[108:110])
		securityBufferLength := binary.LittleEndian.Uint16(data[110:112])

		if securityBufferOffset > 0 && securityBufferLength > 0 {
			offset := int(securityBufferOffset) + 4
			if offset < len(data)+4 && offset+int(securityBufferLength) <= len(data)+4 {
				result.HasNTLM = true
				result.NegotiationLog.AuthenticationTypes = []string{"1.3.6.1.4.1.311.2.2.10"}
			}
		}
	}

	return result, nil
}

// extractNTLMInfo attempts to obtain the NTLM challenge via SESSION_SETUP.
// Reuses the existing connection (negotiate already done on it).
func extractNTLMInfo(conn net.Conn, result *SMBResult) error {
	// Send SESSION_SETUP request with NTLMSSP_NEGOTIATE on the same connection
	sessionSetup := buildSMB2SessionSetupRequest()
	if _, err := conn.Write(sessionSetup); err != nil {
		return err
	}

	// Read full SESSION_SETUP response
	buf, err := readSMBMessage(conn)
	if err != nil {
		return err
	}

	// Need at least NetBIOS header (4) + SMB2 header (64) + session setup response (8)
	if len(buf) < 76 {
		return fmt.Errorf("session setup response too short")
	}

	data := buf[4:] // Skip NetBIOS header

	// Check for STATUS_MORE_PROCESSING_REQUIRED (0xC0000016)
	status := binary.LittleEndian.Uint32(data[8:12])
	if status != 0xC0000016 {
		return fmt.Errorf("unexpected status: 0x%08x", status)
	}

	// Parse session setup response
	if len(data) < 72 {
		return fmt.Errorf("session setup data too short")
	}

	securityBufferOffset := binary.LittleEndian.Uint16(data[68:70])
	securityBufferLength := binary.LittleEndian.Uint16(data[70:72])

	if securityBufferOffset == 0 || securityBufferLength == 0 {
		return fmt.Errorf("no security buffer in response")
	}

	offset := int(securityBufferOffset)
	if offset >= len(data) || offset+int(securityBufferLength) > len(data) {
		return fmt.Errorf("security buffer out of bounds")
	}

	secBuf := data[offset : offset+int(securityBufferLength)]

	// Find NTLMSSP in the security buffer (may be wrapped in SPNEGO/GSS-API)
	ntlmData := secBuf
	if idx := bytes.Index(secBuf, []byte("NTLMSSP\x00")); idx > 0 {
		ntlmData = secBuf[idx:]
	}

	targetName, nbComputerName, nbDomainName, dnsComputerName, dnsDomainName, osVer, err := parseNTLMChallengeMessage(ntlmData)
	if err != nil {
		return err
	}

	if targetName != "" {
		result.TargetName = targetName
	}

	if osVer != nil {
		result.OSVersion = formatOSVersion(osVer)
	}

	// Start with NetBIOS computer name
	if nbComputerName != "" && !isInvalidName(nbComputerName) {
		result.NetBIOSName = nbComputerName
	}

	// DNS Computer name might be more reliable
	if dnsComputerName != "" && !isInvalidName(dnsComputerName) && len(dnsComputerName) > 2 {
		parts := strings.Split(dnsComputerName, ".")
		if len(parts) > 0 && parts[0] != "" && len(parts[0]) > 2 {
			if result.NetBIOSName == "" || len(parts[0]) > len(result.NetBIOSName) {
				result.NetBIOSName = parts[0]
			}
		}
	}

	// Domain names
	if nbDomainName != "" && !isInvalidName(nbDomainName) {
		if nbDomainName != result.NetBIOSName {
			result.DomainName = nbDomainName
		}
	}
	if dnsDomainName != "" && !isInvalidName(dnsDomainName) {
		result.DomainName = dnsDomainName
	}

	// Extract negotiate flags for logging
	if len(ntlmData) >= 24 {
		negotiateFlags := binary.LittleEndian.Uint32(ntlmData[20:24])
		result.SessionSetupLog = &SessionSetupLog{
			ProtocolID:     []byte(SMB2ProtocolID),
			Status:         status,
			Command:        SMB2SessionSetup,
			NegotiateFlags: negotiateFlags,
			TargetName:     result.TargetName,
		}
	}

	return nil
}

// buildSMB2SessionSetupRequest builds an SMB2 SESSION_SETUP request with NTLMSSP_NEGOTIATE
func buildSMB2SessionSetupRequest() []byte {
	// NetBIOS header
	netbios := make([]byte, 4)

	// SMB2 Header (64 bytes)
	header := make([]byte, 64)
	copy(header[0:4], []byte(SMB2ProtocolID))
	binary.LittleEndian.PutUint16(header[4:6], 64)
	binary.LittleEndian.PutUint16(header[12:14], SMB2SessionSetup)
	binary.LittleEndian.PutUint16(header[14:16], 1)
	binary.LittleEndian.PutUint64(header[24:32], 1)

	// SMB2 SESSION_SETUP Request (24 bytes)
	// Structure: StructureSize(2) + Flags(1) + SecurityMode(1) + Capabilities(4) +
	//            Channel(4) + SecurityBufferOffset(2) + SecurityBufferLength(2) + PreviousSessionId(8)
	sessionSetup := make([]byte, 24)
	binary.LittleEndian.PutUint16(sessionSetup[0:2], 25)   // StructureSize (always 25)
	sessionSetup[2] = 0                                    // Flags (1 byte)
	sessionSetup[3] = 0                                    // SecurityMode (1 byte)
	binary.LittleEndian.PutUint32(sessionSetup[4:8], 0)    // Capabilities
	binary.LittleEndian.PutUint32(sessionSetup[8:12], 0)   // Channel
	binary.LittleEndian.PutUint16(sessionSetup[12:14], 88) // SecurityBufferOffset (from start of header)
	binary.LittleEndian.PutUint16(sessionSetup[14:16], 40) // SecurityBufferLength
	binary.LittleEndian.PutUint64(sessionSetup[16:24], 0)  // PreviousSessionId

	// NTLMSSP_NEGOTIATE (based on go-smb2 implementation)
	// Structure: Signature(8) + MessageType(4) + Flags(4) + DomainNameFields(8) + WorkstationFields(8) + Version(8)
	ntlmssp := make([]byte, 40)
	copy(ntlmssp[0:8], []byte("NTLMSSP\x00"))
	binary.LittleEndian.PutUint32(ntlmssp[8:12], 1) // NTLMSSP_NEGOTIATE

	// Flags from go-smb2: NEGOTIATE_56 | KEY_EXCH | 128 | TARGET_INFO | EXTENDED_SESSIONSECURITY |
	//                     ALWAYS_SIGN | NTLM | SIGN | REQUEST_TARGET | UNICODE | VERSION
	// = 0x80000000 | 0x40000000 | 0x20000000 | 0x00800000 | 0x00080000 | 0x00008000 | 0x00000200 | 0x00000010 | 0x00000004 | 0x00000001 | 0x02000000
	binary.LittleEndian.PutUint32(ntlmssp[12:16], 0xe2888215)

	// DomainNameFields (8 bytes) - empty
	binary.LittleEndian.PutUint16(ntlmssp[16:18], 0) // Length
	binary.LittleEndian.PutUint16(ntlmssp[18:20], 0) // MaxLength
	binary.LittleEndian.PutUint32(ntlmssp[20:24], 0) // BufferOffset

	// WorkstationFields (8 bytes) - empty
	binary.LittleEndian.PutUint16(ntlmssp[24:26], 0) // Length
	binary.LittleEndian.PutUint16(ntlmssp[26:28], 0) // MaxLength
	binary.LittleEndian.PutUint32(ntlmssp[28:32], 0) // BufferOffset

	// Version (8 bytes) - Windows 10.0 Build 19041
	ntlmssp[32] = 0x0a                                   // Major: 10
	ntlmssp[33] = 0x00                                   // Minor: 0
	binary.LittleEndian.PutUint16(ntlmssp[34:36], 19041) // Build
	ntlmssp[36] = 0x00                                   // Reserved
	ntlmssp[37] = 0x00                                   // Reserved
	ntlmssp[38] = 0x00                                   // Reserved
	ntlmssp[39] = 0x0f                                   // NTLMRevisionCurrent

	payload := append(header, sessionSetup...)
	payload = append(payload, ntlmssp...)

	// Set NetBIOS length
	length := len(payload)
	netbios[1] = byte(length >> 16)
	netbios[2] = byte(length >> 8)
	netbios[3] = byte(length)

	return append(netbios, payload...)
}

// decodeUTF16LE decodes UTF-16LE bytes to string
func decodeUTF16LE(b []byte) string {
	if len(b) == 0 || len(b)%2 != 0 {
		return ""
	}

	// Convert bytes to uint16 slice
	u16 := make([]uint16, len(b)/2)
	for i := 0; i < len(b); i += 2 {
		u16[i/2] = binary.LittleEndian.Uint16(b[i : i+2])
	}

	// Decode UTF-16LE to string
	decoded := string(utf16.Decode(u16))

	// Trim null terminators and whitespace
	decoded = strings.TrimRight(decoded, "\x00")
	decoded = strings.TrimSpace(decoded)

	return decoded
}

// formatOSVersion formats the OS version from NTLM into a readable string
func formatOSVersion(osVer *OSVersion) string {
	if osVer == nil {
		return ""
	}

	// Samba often reports build 0 - detect this case
	if osVer.Build == 0 {
		return "Samba"
	}

	// Map Windows versions to friendly names
	var osName string
	switch {
	case osVer.Major == 10 && osVer.Minor == 0:
		// Windows 10 / Server 2016+
		switch {
		case osVer.Build >= 22000:
			osName = "Windows 11"
		case osVer.Build >= 20348:
			osName = "Windows Server 2022"
		case osVer.Build >= 19041:
			osName = "Windows 10"
		case osVer.Build >= 17763:
			osName = "Windows Server 2019"
		case osVer.Build >= 14393:
			osName = "Windows Server 2016"
		default:
			osName = "Windows 10"
		}
		return fmt.Sprintf("%s (build %d)", osName, osVer.Build)
	case osVer.Major == 6 && osVer.Minor == 3:
		return fmt.Sprintf("Windows 8.1 / Server 2012 R2 (build %d)", osVer.Build)
	case osVer.Major == 6 && osVer.Minor == 2:
		return fmt.Sprintf("Windows 8 / Server 2012 (build %d)", osVer.Build)
	case osVer.Major == 6 && osVer.Minor == 1:
		return fmt.Sprintf("Windows 7 / Server 2008 R2 (build %d)", osVer.Build)
	case osVer.Major == 6 && osVer.Minor == 0:
		return fmt.Sprintf("Windows Vista / Server 2008 (build %d)", osVer.Build)
	case osVer.Major == 5 && osVer.Minor == 2:
		return fmt.Sprintf("Windows XP / Server 2003 (build %d)", osVer.Build)
	case osVer.Major == 5 && osVer.Minor == 1:
		return fmt.Sprintf("Windows XP (build %d)", osVer.Build)
	case osVer.Major == 5 && osVer.Minor == 0:
		return fmt.Sprintf("Windows 2000 (build %d)", osVer.Build)
	case osVer.Major == 4 && osVer.Build == 0:
		// Samba often reports 4.0
		return "Samba"
	default:
		return fmt.Sprintf("Windows %d.%d (build %d)", osVer.Major, osVer.Minor, osVer.Build)
	}
}

// isInvalidName checks if a name is invalid (empty, too short, or contains non-printable/corrupted characters)
func isInvalidName(s string) bool {
	// Empty or too short
	if len(s) < 1 {
		return true
	}

	// Check for null bytes or other control characters (0x00-0x1F, 0x7F-0x9F)
	for _, r := range s {
		if r < 32 || (r >= 0x7F && r <= 0x9F) {
			return true
		}
	}

	// Check for replacement character (indicates decode failure)
	if strings.Contains(s, "\ufffd") {
		return true
	}

	return false
}

// extractNameFromGUID extracts the machine name from a server GUID
// Samba servers often put the hostname in the first bytes of the GUID
func extractNameFromGUID(guid []byte) string {
	if len(guid) < 8 {
		return ""
	}

	// Extract printable ASCII characters from the beginning of the GUID
	var name string
	for i := 0; i < len(guid); i++ {
		// Stop at null byte
		if guid[i] == 0 {
			break
		}
		// Only keep printable ASCII characters
		if guid[i] >= 32 && guid[i] <= 126 {
			name += string(guid[i])
		} else {
			break
		}
	}

	// Validate that we got a reasonable hostname (at least 2 chars, alphanumeric)
	if len(name) >= 2 {
		return strings.ToUpper(name)
	}

	return ""
}

// parseSecurityMode decodes SMB security mode flags
func parseSecurityMode(mode uint16) *SecurityMode {
	sm := &SecurityMode{
		MessageSigningEnabled:  (mode & 0x01) != 0,
		MessageSigningRequired: (mode & 0x02) != 0,
	}

	// Build description similar to nmap output
	if sm.MessageSigningRequired {
		sm.Description = "Message signing enabled and required"
	} else if sm.MessageSigningEnabled {
		sm.Description = "Message signing enabled but not required"
	} else {
		sm.Description = "Message signing disabled"
	}

	return sm
}

// formatFileTime converts Windows FILETIME (100-nanosecond intervals since 1601-01-01) to ISO 8601
func formatFileTime(ft uint64) string {
	if ft == 0 {
		return "N/A"
	}

	// Windows FILETIME epoch: January 1, 1601
	// Unix epoch: January 1, 1970
	// Difference: 11644473600 seconds
	const windowsToUnixEpoch = 116444736000000000

	if ft < windowsToUnixEpoch {
		return "N/A"
	}

	// Convert to Unix timestamp (nanoseconds)
	unixNano := int64(ft-windowsToUnixEpoch) * 100

	// Convert to time.Time
	t := time.Unix(0, unixNano)

	// Format as ISO 8601 (similar to nmap: 2025-11-29T21:48:37)
	return t.UTC().Format("2006-01-02T15:04:05")
}

// ========== Share Enumeration Functions ==========

// tryEnumerateShares tries different methods to enumerate shares
func tryEnumerateShares(host string, port int) ([]ShareInfo, string, error) {
	// Try 1: SMBv1 RAP (works on older servers and some Samba)
	shares, err := enumerateSharesSMBv1RAP(host, port)
	if err == nil && len(shares) > 0 {
		return shares, "SMBv1 RAP (anonymous)", nil
	}

	// Try 2: Null session with SMB2/3 (using go-smb)
	shares, err = listSMBSharesNullSession(host, port)
	if err == nil && len(shares) > 0 {
		return shares, "Null Session (SMB2/3)", nil
	}

	// Try 3: Guest account
	shares, err = listSMBSharesWithGuest("guest", host, port)
	if err == nil && len(shares) > 0 {
		return shares, "Guest Account (SMB2/3)", nil
	}

	return nil, "", fmt.Errorf("all enumeration methods failed")
}

// enumerateSharesSMBv1RAP enumerates shares using SMBv1 RAP protocol
func enumerateSharesSMBv1RAP(host string, port int) ([]ShareInfo, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 10*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Port 139 requires NetBIOS session setup first
	if port == 139 {
		if err := setupNetBIOSSession(conn); err != nil {
			return nil, fmt.Errorf("NetBIOS session setup failed: %w", err)
		}
	}

	// 1. SMBv1 Negotiate
	negotiateReq := buildSMBv1NegotiateRequest()
	if _, err := conn.Write(negotiateReq); err != nil {
		return nil, err
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}

	if n < 37 || buf[36] == 0 {
		return nil, fmt.Errorf("server rejected SMBv1")
	}

	// 2. Session Setup (anonymous)
	sessionSetupReq := buildSMBv1SessionSetupRequest()
	if _, err := conn.Write(sessionSetupReq); err != nil {
		return nil, err
	}

	n, err = conn.Read(buf)
	if err != nil {
		return nil, err
	}

	if n < 34 {
		return nil, fmt.Errorf("session setup failed")
	}

	uid := binary.LittleEndian.Uint16(buf[32:34])

	// 3. Tree Connect to IPC$
	treeConnectReq := buildSMBv1TreeConnectRequest(uid, host)
	if _, err := conn.Write(treeConnectReq); err != nil {
		return nil, err
	}

	n, err = conn.Read(buf)
	if err != nil {
		return nil, err
	}

	if n < 30 {
		return nil, fmt.Errorf("tree connect failed")
	}

	tid := binary.LittleEndian.Uint16(buf[28:30])

	// 4. RAP NetShareEnum
	rapReq := buildSMBv1RAPNetShareEnumRequest(uid, tid)
	if _, err := conn.Write(rapReq); err != nil {
		return nil, err
	}

	n, err = conn.Read(buf)
	if err != nil {
		return nil, err
	}

	return parseSMBv1RAPResponse(buf[:n])
}

// buildSMBv1NegotiateRequest builds a SMBv1 Negotiate Protocol request
func buildSMBv1NegotiateRequest() []byte {
	var buf bytes.Buffer

	// NetBIOS Session Header
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})

	// SMB Header (32 bytes)
	buf.Write([]byte{0xFF, 'S', 'M', 'B'}) // Protocol
	buf.WriteByte(0x72)                    // Command: Negotiate Protocol
	buf.Write(make([]byte, 4))             // Status
	buf.WriteByte(0x18)                    // Flags
	buf.Write([]byte{0x01, 0x28})          // Flags2
	buf.Write(make([]byte, 12))            // PID, Signature
	buf.Write(make([]byte, 2))             // Reserved
	buf.Write(make([]byte, 2))             // TID
	buf.Write(make([]byte, 2))             // PID
	buf.Write(make([]byte, 2))             // UID
	buf.Write(make([]byte, 2))             // MID

	// Parameters
	buf.WriteByte(0) // Word Count

	// Data - SMB dialects
	var dialectsData bytes.Buffer
	dialectsData.Write([]byte("\x02PC NETWORK PROGRAM 1.0\x00"))
	dialectsData.Write([]byte("\x02LANMAN1.0\x00"))
	dialectsData.Write([]byte("\x02Windows for Workgroups 3.1a\x00"))
	dialectsData.Write([]byte("\x02LM1.2X002\x00"))
	dialectsData.Write([]byte("\x02LANMAN2.1\x00"))
	dialectsData.Write([]byte("\x02NT LM 0.12\x00"))

	dialectBytes := dialectsData.Bytes()
	binary.Write(&buf, binary.LittleEndian, uint16(len(dialectBytes)))
	buf.Write(dialectBytes)

	// Update NetBIOS length
	data := buf.Bytes()
	length := len(data) - 4
	data[1] = byte(length >> 16)
	data[2] = byte(length >> 8)
	data[3] = byte(length)

	return data
}

// buildSMBv1SessionSetupRequest builds a Session Setup AndX Request (anonymous)
func buildSMBv1SessionSetupRequest() []byte {
	var buf bytes.Buffer

	// NetBIOS Header
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})

	// SMB Header
	buf.Write([]byte{0xFF, 'S', 'M', 'B'})
	buf.WriteByte(0x73) // Session Setup AndX
	buf.Write(make([]byte, 4))
	buf.WriteByte(0x18)
	buf.Write([]byte{0x01, 0x28})
	buf.Write(make([]byte, 12))
	buf.Write(make([]byte, 2))
	buf.Write(make([]byte, 2))
	buf.Write(make([]byte, 2))
	buf.Write(make([]byte, 2))
	buf.Write(make([]byte, 2))

	// Parameters
	buf.WriteByte(13)             // Word Count
	buf.WriteByte(0xFF)           // AndX Command: No further commands
	buf.WriteByte(0)              // Reserved
	buf.Write([]byte{0, 0})       // AndX Offset
	buf.Write([]byte{0xFF, 0xFF}) // Max Buffer
	buf.Write([]byte{0x02, 0x00}) // Max Mpx Count
	buf.Write([]byte{0x01, 0x00}) // VC Number
	buf.Write(make([]byte, 4))    // Session Key
	buf.Write([]byte{0, 0})       // ANSI Password Length
	buf.Write([]byte{0, 0})       // Unicode Password Length
	buf.Write(make([]byte, 4))    // Reserved
	buf.Write([]byte{0, 0, 0, 0}) // Capabilities

	// Data (empty for anonymous)
	buf.Write([]byte{0, 0})

	data := buf.Bytes()
	length := len(data) - 4
	data[1] = byte(length >> 16)
	data[2] = byte(length >> 8)
	data[3] = byte(length)

	return data
}

// buildSMBv1TreeConnectRequest builds a Tree Connect AndX Request for IPC$
func buildSMBv1TreeConnectRequest(uid uint16, host string) []byte {
	var buf bytes.Buffer

	// NetBIOS Header
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})

	// SMB Header
	buf.Write([]byte{0xFF, 'S', 'M', 'B'})
	buf.WriteByte(0x75) // Tree Connect AndX
	buf.Write(make([]byte, 4))
	buf.WriteByte(0x18)
	buf.Write([]byte{0x01, 0x28})
	buf.Write(make([]byte, 12))
	buf.Write(make([]byte, 2))
	buf.Write(make([]byte, 2))
	buf.Write(make([]byte, 2))

	// UID
	uidBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(uidBytes, uid)
	buf.Write(uidBytes)
	buf.Write(make([]byte, 2))

	// Parameters
	buf.WriteByte(4)    // Word Count
	buf.WriteByte(0xFF) // AndX Command
	buf.WriteByte(0)
	buf.Write([]byte{0, 0}) // AndX Offset
	buf.Write([]byte{0, 0}) // Flags
	buf.Write([]byte{1, 0}) // Password Length

	// Data
	path := fmt.Sprintf("\\\\%s\\IPC$", strings.ToUpper(host))
	service := "IPC"

	dataBytes := []byte{0} // Empty password
	dataBytes = append(dataBytes, []byte(path)...)
	dataBytes = append(dataBytes, 0)
	dataBytes = append(dataBytes, []byte(service)...)
	dataBytes = append(dataBytes, 0)

	buf.Write([]byte{byte(len(dataBytes)), byte(len(dataBytes) >> 8)})
	buf.Write(dataBytes)

	data := buf.Bytes()
	length := len(data) - 4
	data[1] = byte(length >> 16)
	data[2] = byte(length >> 8)
	data[3] = byte(length)

	return data
}

// buildSMBv1RAPNetShareEnumRequest builds a RAP NetShareEnum request
func buildSMBv1RAPNetShareEnumRequest(uid, tid uint16) []byte {
	var buf bytes.Buffer

	// NetBIOS Header
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})

	// SMB Header
	buf.Write([]byte{0xFF, 'S', 'M', 'B'})
	buf.WriteByte(0x25) // Transaction
	buf.Write(make([]byte, 4))
	buf.WriteByte(0x18)
	buf.Write([]byte{0x01, 0x28})
	buf.Write(make([]byte, 12))
	buf.Write(make([]byte, 2))

	// TID
	tidBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(tidBytes, tid)
	buf.Write(tidBytes)
	buf.Write(make([]byte, 2))

	// UID
	uidBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(uidBytes, uid)
	buf.Write(uidBytes)
	buf.Write(make([]byte, 2))

	// Transaction Parameters
	buf.WriteByte(14)             // Word Count
	buf.Write([]byte{0, 0})       // Total Parameter Count
	buf.Write([]byte{0, 0})       // Total Data Count
	buf.Write([]byte{0xFF, 0xFF}) // Max Parameter Count
	buf.Write([]byte{0xFF, 0xFF}) // Max Data Count
	buf.WriteByte(0)              // Max Setup Count
	buf.WriteByte(0)              // Reserved
	buf.Write([]byte{0, 0})       // Flags
	buf.Write(make([]byte, 4))    // Timeout
	buf.Write([]byte{0, 0})       // Reserved2
	buf.Write([]byte{0, 0})       // Parameter Count
	buf.Write([]byte{0, 0})       // Parameter Offset
	buf.Write([]byte{0, 0})       // Data Count
	buf.Write([]byte{0, 0})       // Data Offset
	buf.WriteByte(2)              // Setup Count
	buf.WriteByte(0)              // Reserved3

	// Setup: RAP call
	buf.Write([]byte{0, 0}) // Function: NetShareEnum
	buf.Write([]byte{0, 0}) // FID

	// RAP data
	rapData := buildRAPNetShareEnumData()
	buf.Write([]byte{byte(len(rapData)), byte(len(rapData) >> 8)})
	buf.Write(rapData)

	data := buf.Bytes()
	length := len(data) - 4
	data[1] = byte(length >> 16)
	data[2] = byte(length >> 8)
	data[3] = byte(length)

	return data
}

// buildRAPNetShareEnumData builds RAP NetShareEnumAll data
func buildRAPNetShareEnumData() []byte {
	var buf bytes.Buffer

	buf.Write([]byte("WrLeh")) // Parameter descriptor
	buf.WriteByte(0)
	buf.Write([]byte("B13BWz")) // Return descriptor
	buf.WriteByte(0)
	buf.Write([]byte{1, 0})       // Info level 1
	buf.Write([]byte{0xFF, 0xFF}) // Receive buffer size

	return buf.Bytes()
}

// parseSMBv1RAPResponse parses RAP response to extract shares
func parseSMBv1RAPResponse(data []byte) ([]ShareInfo, error) {
	if len(data) < 37 {
		return nil, fmt.Errorf("response too short")
	}

	if string(data[4:8]) != "\xFFSMB" {
		return nil, fmt.Errorf("invalid SMB signature")
	}

	// Check NT status
	status := binary.LittleEndian.Uint32(data[9:13])
	if status != 0 {
		return nil, fmt.Errorf("SMB error status: 0x%08x", status)
	}

	wordCount := data[36]
	paramsOffset := 37 + int(wordCount)*2

	if len(data) < paramsOffset+2 {
		return nil, fmt.Errorf("data truncated")
	}

	byteCount := binary.LittleEndian.Uint16(data[paramsOffset : paramsOffset+2])
	dataStart := paramsOffset + 2

	if len(data) < dataStart+int(byteCount) {
		return nil, fmt.Errorf("data truncated")
	}

	rapData := data[dataStart : dataStart+int(byteCount)]

	if len(rapData) < 8 {
		return nil, fmt.Errorf("RAP response too short")
	}

	rapStatus := binary.LittleEndian.Uint16(rapData[0:2])
	if rapStatus != 0 {
		return nil, fmt.Errorf("RAP error: %d", rapStatus)
	}

	converter := binary.LittleEndian.Uint16(rapData[2:4])
	entryCount := binary.LittleEndian.Uint16(rapData[4:6])

	if entryCount == 0 {
		return nil, nil
	}

	shares := []ShareInfo{}
	offset := 8

	for i := 0; i < int(entryCount); i++ {
		if offset+20 > len(rapData) {
			break
		}

		entry := rapData[offset : offset+20]

		// Name (13 bytes)
		nameBytes := entry[0:13]
		name := string(bytes.TrimRight(nameBytes, "\x00"))

		// Type (2 bytes)
		shareType := binary.LittleEndian.Uint16(entry[14:16])

		// Comment pointer (4 bytes)
		commentPtr := binary.LittleEndian.Uint32(entry[16:20])

		// Extract comment
		comment := ""
		if commentPtr != 0 && converter != 0 {
			commentOffset := int(commentPtr) - int(converter)
			if commentOffset >= 0 && commentOffset < len(rapData) {
				commentEnd := commentOffset
				for commentEnd < len(rapData) && rapData[commentEnd] != 0 {
					commentEnd++
				}
				if commentEnd > commentOffset {
					comment = string(rapData[commentOffset:commentEnd])
				}
			}
		}

		// Convert type to string
		typeStr := "Unknown"
		switch shareType & 0x7FFF {
		case 0:
			typeStr = "Disk"
		case 1:
			typeStr = "Print"
		case 2:
			typeStr = "Device"
		case 3:
			typeStr = "IPC"
		}
		if shareType&0x8000 != 0 {
			typeStr += " (Hidden)"
		}

		shares = append(shares, ShareInfo{
			Name:    name,
			Type:    typeStr,
			Comment: comment,
		})

		offset += 20
	}

	return shares, nil
}

// listSMBSharesNullSession enumerates shares using null session (empty credentials)
// This works on misconfigured servers that allow anonymous access
func listSMBSharesNullSession(host string, port int) ([]ShareInfo, error) {
	var shares []ShareInfo

	// Configure null session: empty username and password
	options := smb.Options{
		Host: host,
		Port: port,
		Initiator: &spnego.NTLMInitiator{
			User:     "", // Empty for null session
			Password: "",
			Domain:   "",
		},
		DisableEncryption: true,
		ForceSMB2:         false, // Allow negotiation
	}

	// Establish connection
	session, err := smb.NewConnection(options)
	if err != nil {
		return nil, fmt.Errorf("null session connection failed: %w", err)
	}
	defer session.Close()

	// Check if anonymous auth was accepted
	if !session.IsAuthenticated() {
		return nil, fmt.Errorf("null session rejected by server")
	}

	// Connect to IPC$ share
	share := "IPC$"
	err = session.TreeConnect(share)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to IPC$: %w", err)
	}
	defer session.TreeDisconnect(share)

	// Open RPC pipe for MS-SRVS
	f, err := session.OpenFile(share, mssrvs.MSRPCSrvSvcPipe)
	if err != nil {
		return nil, fmt.Errorf("failed to open RPC pipe: %w", err)
	}
	defer f.CloseFile()

	// Establish DCERPC connection
	bind, err := dcerpc.Bind(f, mssrvs.MSRPCUuidSrvSvc,
		mssrvs.MSRPCSrvSvcMajorVersion,
		mssrvs.MSRPCSrvSvcMinorVersion,
		dcerpc.MSRPCUuidNdr)
	if err != nil {
		return nil, fmt.Errorf("DCERPC bind failed: %w", err)
	}

	rpccon := mssrvs.NewRPCCon(bind)

	// Enumerate all shares
	smbShares, err := rpccon.NetShareEnumAll(host)
	if err != nil {
		return nil, fmt.Errorf("share enumeration failed: %w", err)
	}

	// Build result list
	for _, s := range smbShares {
		shares = append(shares, ShareInfo{
			Name:    s.Name,
			Comment: s.Comment,
			Type:    s.Type,
		})
	}

	return shares, nil
}

// listSMBSharesWithGuest attempts guest access (variant of null session)
func listSMBSharesWithGuest(user string, host string, port int) ([]ShareInfo, error) {
	var shares []ShareInfo

	// Configure guest access
	options := smb.Options{
		Host: host,
		Port: port,
		Initiator: &spnego.NTLMInitiator{
			User:     user, // Guest username
			Password: "",   // No password
			Domain:   "",
		},
		DisableEncryption: true,
		ForceSMB2:         false,
	}

	session, err := smb.NewConnection(options)
	if err != nil {
		return nil, fmt.Errorf("guest connection failed: %w", err)
	}
	defer session.Close()

	if !session.IsAuthenticated() {
		return nil, fmt.Errorf("guest access rejected")
	}

	share := "IPC$"
	err = session.TreeConnect(share)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to IPC$: %w", err)
	}
	defer session.TreeDisconnect(share)

	f, err := session.OpenFile(share, mssrvs.MSRPCSrvSvcPipe)
	if err != nil {
		return nil, fmt.Errorf("failed to open pipe: %w", err)
	}
	defer f.CloseFile()

	bind, err := dcerpc.Bind(f, mssrvs.MSRPCUuidSrvSvc,
		mssrvs.MSRPCSrvSvcMajorVersion,
		mssrvs.MSRPCSrvSvcMinorVersion,
		dcerpc.MSRPCUuidNdr)
	if err != nil {
		return nil, fmt.Errorf("DCERPC bind failed: %w", err)
	}

	rpccon := mssrvs.NewRPCCon(bind)
	smbShares, err := rpccon.NetShareEnumAll(host)
	if err != nil {
		return nil, fmt.Errorf("enumeration failed: %w", err)
	}

	for _, s := range smbShares {
		shares = append(shares, ShareInfo{
			Name:    s.Name,
			Comment: s.Comment,
			Type:    s.Type,
		})
	}

	return shares, nil
}
