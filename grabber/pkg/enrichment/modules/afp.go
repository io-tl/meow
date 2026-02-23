package modules

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"meow/grabber/pkg/enrichment/modules/helpers"
)

// AFP DSI Request constants
const (
	DSI_REQUEST      = 0x00
	DSI_RESPONSE     = 0x01
	DSI_OPENSESSION  = 0x04
	DSI_CLOSESESSION = 0x01
	DSI_COMMAND      = 0x02
	DSI_GETSTATUS    = 0x03
	DSI_WRITE        = 0x06
)

// AFP Command constants
const (
	FP_GET_SERVER_INFO     = 0x0f
	FP_GET_SRV_PARMS       = 0x10
	FP_OPEN_VOL            = 0x18
	FP_GET_FILE_DIR_PARAMS = 0x22
	FP_CLOSE_VOL           = 0x02
)

// AFP Server Flags (from Nmap afp.lua)
const (
	SERVERFLAG_COPY_FILE            = 0x0001
	SERVERFLAG_CHANGEABLE_PASSWORDS = 0x0002
	SERVERFLAG_NO_PASSWORD_SAVING   = 0x0004
	SERVERFLAG_SERVER_MESSAGES      = 0x0008
	SERVERFLAG_SERVER_SIGNATURE     = 0x0010
	SERVERFLAG_TCP_OVER_IP          = 0x0020
	SERVERFLAG_SERVER_NOTIFICATIONS = 0x0040
	SERVERFLAG_RECONNECT            = 0x0080
	SERVERFLAG_OPEN_DIRECTORY       = 0x0100
	SERVERFLAG_UTF8_SERVER_NAME     = 0x0200
	SERVERFLAG_UUIDS                = 0x0400
	SERVERFLAG_SUPER_CLIENT         = 0x8000
)

// AFP Volume Bitmap constants
const (
	VOL_BITMAP_ATTRIBUTES           = 0x0001
	VOL_BITMAP_SIGNATURE            = 0x0002
	VOL_BITMAP_CREATION_DATE        = 0x0004
	VOL_BITMAP_MODIFICATION_DATE    = 0x0008
	VOL_BITMAP_BACKUP_DATE          = 0x0010
	VOL_BITMAP_ID                   = 0x0020
	VOL_BITMAP_BYTES_FREE           = 0x0040
	VOL_BITMAP_BYTES_TOTAL          = 0x0080
	VOL_BITMAP_NAME                 = 0x0100
	VOL_BITMAP_EXTENDED_BYTES_FREE  = 0x0200
	VOL_BITMAP_EXTENDED_BYTES_TOTAL = 0x0400
	VOL_BITMAP_BLOCK_SIZE           = 0x0800
)

// AFP Directory Bitmap constants
const (
	DIR_BITMAP_ATTRIBUTES        = 0x0001
	DIR_BITMAP_PARENT_DIR_ID     = 0x0002
	DIR_BITMAP_CREATION_DATE     = 0x0004
	DIR_BITMAP_MODIFICATION_DATE = 0x0008
	DIR_BITMAP_BACKUP_DATE       = 0x0010
	DIR_BITMAP_FINDER_INFO       = 0x0020
	DIR_BITMAP_LONG_NAME         = 0x0040
	DIR_BITMAP_SHORT_NAME        = 0x0080
	DIR_BITMAP_NODE_ID           = 0x0100
	DIR_BITMAP_OFFSPRING_COUNT   = 0x0200
	DIR_BITMAP_OWNER_ID          = 0x0400
	DIR_BITMAP_GROUP_ID          = 0x0800
	DIR_BITMAP_ACCESS_RIGHTS     = 0x1000
	DIR_BITMAP_UTF8_NAME         = 0x2000
	DIR_BITMAP_UNIX_PRIVILEGES   = 0x8000
)

// AFP ACL constants
const (
	ACL_OWNER_SEARCH = 0x000001
	ACL_OWNER_READ   = 0x000002
	ACL_OWNER_WRITE  = 0x000004

	ACL_GROUP_SEARCH = 0x000100
	ACL_GROUP_READ   = 0x000200
	ACL_GROUP_WRITE  = 0x000400

	ACL_EVERYONE_SEARCH = 0x010000
	ACL_EVERYONE_READ   = 0x020000
	ACL_EVERYONE_WRITE  = 0x040000

	ACL_USER_SEARCH = 0x100000
	ACL_USER_READ   = 0x200000
	ACL_USER_WRITE  = 0x400000

	ACL_BLANK_ACCESS  = 0x1000000
	ACL_USER_IS_OWNER = 0x8000000
)

// AFP UAM constants
var AFP_UAMS = map[string]string{
	"No User Authent":  "No User Authent",
	"Cleartxt Passwrd": "Cleartxt Passwrd",
	"DHCAST128":        "DHCAST128",
	"DHX2":             "DHX2",
	"2-Way Randnum":    "2-Way Randnum",
	"Randnum Exchange": "Randnum Exchange",
	"Kerberos":         "Kerberos",
	"Client Krb v2":    "Client Krb v2",
	"Recon1":           "Recon1",
}

// AFPShareInfo represents information about an AFP share/volume
type AFPShareInfo struct {
	Name                string   `json:"name"`
	OwnerPermissions    []string `json:"owner_permissions,omitempty"`
	GroupPermissions    []string `json:"group_permissions,omitempty"`
	EveryonePermissions []string `json:"everyone_permissions,omitempty"`
	UserPermissions     []string `json:"user_permissions,omitempty"`
	Options             []string `json:"options,omitempty"`
}

// AFPModule implements Apple Filing Protocol enrichment module
type AFPModule struct {
	BaseModule
}

type AFPResult struct {
	Protocol       string   `json:"protocol"`
	AFPVersion     string   `json:"afp_version,omitempty"`
	MachineType    string   `json:"machine_type,omitempty"`
	ComputerName   string   `json:"computer_name,omitempty"`
	DNSName        string   `json:"dns_name,omitempty"`
	CertificateCN  string   `json:"certificate_cn,omitempty"`
	ServerName     string   `json:"server_name,omitempty"`
	UTF8ServerName string   `json:"utf8_server_name,omitempty"`
	TLS            *TLSInfo `json:"tls,omitempty"`
	StatusFlags    []string `json:"status_flags,omitempty"`

	// AFP Server Flags (matching Nmap output format)
	SuperClient         bool `json:"super_client,omitempty"`
	UUIDs               bool `json:"uuids,omitempty"`
	UTF8ServerNameFlag  bool `json:"utf8_server_name_flag,omitempty"`
	OpenDirectory       bool `json:"open_directory,omitempty"`
	Reconnect           bool `json:"reconnect,omitempty"`
	ServerNotifications bool `json:"server_notifications,omitempty"`
	TCPoverIP           bool `json:"tcp_ip,omitempty"`
	ServerSignature     bool `json:"server_signature,omitempty"`
	ServerMessages      bool `json:"server_messages,omitempty"`
	NoPasswordSaving    bool `json:"no_password_saving,omitempty"`
	ChangeablePasswords bool `json:"changeable_passwords,omitempty"`
	CopyFile            bool `json:"copy_file,omitempty"`

	// Detailed server information
	ServerSignatureHex   string   `json:"server_signature_hex,omitempty"`
	SupportedAFPVersions []string `json:"supported_afp_versions,omitempty"`
	UAMs                 []string `json:"uams,omitempty"`
	NetworkAddresses     []string `json:"network_addresses,omitempty"`
	DirectoryNames       []string `json:"directory_names,omitempty"`

	// Share information
	Shares []AFPShareInfo `json:"shares,omitempty"`

	Error string `json:"error,omitempty"`
}

func init() {
	Register(&AFPModule{
		BaseModule: NewBaseModule("afp", []string{}, true, 10*time.Second),
	})
}

func (m *AFPModule) Scan(ip string, port int) (interface{}, error) {
	return scanAFP(ip, port, m.DefaultTimeout())
}

// scanAFP performs AFP enrichment using DSI GetStatus request
func scanAFP(ip string, port int, timeout time.Duration) (*AFPResult, error) {
	result := &AFPResult{
		Protocol: "afp",
	}

	// Perform DSI GetStatus request to get server information
	dsiResult, dsiErr := scanAFPWithDSI(ip, port, timeout)
	if dsiErr == nil {
		// Copy all DSI results to main result
		result = dsiResult
	} else {
		result.Error = fmt.Sprintf("AFP enrichment failed: %v", dsiErr)
		return result, dsiErr
	}

	// Try to get share listing
	shares, shareErr := getAFPShares(ip, port, timeout)
	if shareErr == nil {
		result.Shares = shares
	}

	return result, nil
}

// scanAFPWithDSI performs DSI GetStatus to extract AFP server information
func scanAFPWithDSI(ip string, port int, timeout time.Duration) (*AFPResult, error) {
	result := &AFPResult{
		Protocol: "afp",
	}

	conn, err := helpers.DialTCP(ip, port, timeout)
	if err != nil {
		result.Error = fmt.Sprintf("TCP connection failed: %v", err)
		return result, err
	}
	defer conn.Close()

	// Build DSI GetStatus request with FPGetSrvrInfo command
	request := buildDSIGetStatusRequest()
	_, err = conn.Write(request)
	if err != nil {
		result.Error = fmt.Sprintf("DSI write failed: %v", err)
		return result, err
	}

	// Read response
	response := make([]byte, 4096)
	n, err := conn.Read(response)
	if err != nil {
		result.Error = fmt.Sprintf("DSI read failed: %v", err)
		return result, err
	}

	if n < 16 {
		result.Error = "Response too short"
		return result, fmt.Errorf("AFP response too short")
	}

	// Parse DSI header
	if response[0] != DSI_RESPONSE || response[1] != DSI_GETSTATUS {
		result.Error = "Invalid DSI response"
		return result, fmt.Errorf("invalid DSI response")
	}

	// Extract error code from DSI header
	errorCode := binary.BigEndian.Uint32(response[4:8])
	if errorCode != 0 {
		result.Error = fmt.Sprintf("AFP error: %d", errorCode)
		return result, fmt.Errorf("AFP error: %d", errorCode)
	}

	// Parse AFP server info from response data
	dataLength := binary.BigEndian.Uint32(response[8:12])
	if dataLength > 0 && n >= 16 {
		data := response[16 : 16+dataLength]
		err = parseAFPServerInfo(result, data)
		if err != nil {
			result.Error = fmt.Sprintf("Failed to parse AFP info: %v", err)
			return result, err
		}
	}

	return result, nil
}

// buildDSIGetStatusRequest builds a DSI GetStatus request with FPGetSrvrInfo command
func buildDSIGetStatusRequest() []byte {
	// DSI Header: flags(1) + command(1) + requestID(2) + errorCode(4) + dataLength(4) + reserved(4)
	request := []byte{
		DSI_REQUEST,   // Flags: request
		DSI_GETSTATUS, // Command: GetStatus
		0x00, 0x01,    // Request ID: 1
		0x00, 0x00, 0x00, 0x00, // Error code: 0
		0x00, 0x00, 0x00, 0x02, // Data length: 2
		0x00, 0x00, 0x00, 0x00, // Reserved
	}

	// Data: FPGetSrvrInfo command
	data := []byte{
		FP_GET_SERVER_INFO, // FPGetSrvrInfo command
		0x00,               // Padding
	}

	return append(request, data...)
}

// parseAFPServerInfo parses AFP server information from FPGetSrvrInfo response
func parseAFPServerInfo(result *AFPResult, data []byte) error {
	if len(data) < 20 {
		return fmt.Errorf("data too short")
	}

	pos := 0

	// Parse offsets from header
	offsets := struct {
		machineType       uint16
		afpVersionCount   uint16
		uamCount          uint16
		volumeIconAndMask uint16
	}{}

	offsets.machineType = binary.BigEndian.Uint16(data[pos : pos+2])
	pos += 2
	offsets.afpVersionCount = binary.BigEndian.Uint16(data[pos : pos+2])
	pos += 2
	offsets.uamCount = binary.BigEndian.Uint16(data[pos : pos+2])
	pos += 2
	offsets.volumeIconAndMask = binary.BigEndian.Uint16(data[pos : pos+2])
	pos += 2

	// Parse server flags
	serverFlags := binary.BigEndian.Uint16(data[pos : pos+2])
	pos += 2

	// Parse server name (null-terminated string)
	serverName, err := parsePascalString(data, pos)
	if err == nil {
		result.ServerName = serverName
	}
	pos += len(serverName) + 1

	// Ensure even boundary
	if pos%2 != 0 {
		pos++
	}

	// Parse additional offsets
	var serverSignature, networkAddressesCount, utf8ServerName uint16
	serverSignature = binary.BigEndian.Uint16(data[pos : pos+2])
	pos += 2
	networkAddressesCount = binary.BigEndian.Uint16(data[pos : pos+2])
	pos += 2
	pos += 2 // Skip directoryNamesCount
	utf8ServerName = binary.BigEndian.Uint16(data[pos : pos+2])
	pos += 2

	// Parse server flags into boolean fields
	result.SuperClient = (serverFlags & SERVERFLAG_SUPER_CLIENT) != 0
	result.UUIDs = (serverFlags & SERVERFLAG_UUIDS) != 0
	result.UTF8ServerNameFlag = (serverFlags & SERVERFLAG_UTF8_SERVER_NAME) != 0
	result.OpenDirectory = (serverFlags & SERVERFLAG_OPEN_DIRECTORY) != 0
	result.Reconnect = (serverFlags & SERVERFLAG_RECONNECT) != 0
	result.ServerNotifications = (serverFlags & SERVERFLAG_SERVER_NOTIFICATIONS) != 0
	result.TCPoverIP = (serverFlags & SERVERFLAG_TCP_OVER_IP) != 0
	result.ServerSignature = (serverFlags & SERVERFLAG_SERVER_SIGNATURE) != 0
	result.ServerMessages = (serverFlags & SERVERFLAG_SERVER_MESSAGES) != 0
	result.NoPasswordSaving = (serverFlags & SERVERFLAG_NO_PASSWORD_SAVING) != 0
	result.ChangeablePasswords = (serverFlags & SERVERFLAG_CHANGEABLE_PASSWORDS) != 0
	result.CopyFile = (serverFlags & SERVERFLAG_COPY_FILE) != 0

	// Parse machine type
	if int(offsets.machineType) < len(data) {
		machineType, err := parsePascalString(data, int(offsets.machineType))
		if err == nil {
			result.MachineType = machineType
		}
	}

	// Parse AFP versions
	if int(offsets.afpVersionCount) < len(data) {
		versionCount := data[offsets.afpVersionCount]
		pos = int(offsets.afpVersionCount) + 1
		var versions []string
		for i := 0; i < int(versionCount) && pos < len(data); i++ {
			version, err := parsePascalString(data, pos)
			if err != nil {
				break
			}
			versions = append(versions, version)
			pos += len(version) + 1
		}
		result.SupportedAFPVersions = versions
		if len(versions) > 0 {
			result.AFPVersion = strings.Join(versions, ", ")
		}
	}

	// Parse UAMs
	if int(offsets.uamCount) < len(data) {
		uamCount := data[offsets.uamCount]
		pos = int(offsets.uamCount) + 1
		var uams []string
		for i := 0; i < int(uamCount) && pos < len(data); i++ {
			uam, err := parsePascalString(data, pos)
			if err != nil {
				break
			}
			uams = append(uams, uam)
			pos += len(uam) + 1
		}
		result.UAMs = uams
	}

	// Parse server signature (16 bytes)
	if int(serverSignature)+16 <= len(data) {
		signature := data[serverSignature : serverSignature+16]
		result.ServerSignatureHex = fmt.Sprintf("%x", signature)
	}

	// Parse UTF8 server name
	if int(utf8ServerName) < len(data) {
		utf8Name, err := parseUTF16String(data, int(utf8ServerName))
		if err == nil {
			result.UTF8ServerName = utf8Name
		}
	}

	// Parse network addresses
	if int(networkAddressesCount) < len(data) {
		addrCount := data[networkAddressesCount]
		pos = int(networkAddressesCount) + 1
		var addresses []string
		for i := 0; i < int(addrCount) && pos < len(data); i++ {
			if pos+1 >= len(data) {
				break
			}
			length := int(data[pos])
			tag := data[pos+1]
			pos += 2

			if pos+length > len(data) {
				break
			}

			switch tag {
			case 0x01: // IPv4
				if length >= 4 {
					ip := fmt.Sprintf("%d.%d.%d.%d", data[pos], data[pos+1], data[pos+2], data[pos+3])
					addresses = append(addresses, ip)
				}
			case 0x02: // IPv4 + port
				if length >= 6 {
					ip := fmt.Sprintf("%d.%d.%d.%d", data[pos], data[pos+1], data[pos+2], data[pos+3])
					port := binary.BigEndian.Uint16(data[pos+4 : pos+6])
					addresses = append(addresses, fmt.Sprintf("%s:%d", ip, port))
				}
			case 0x04: // DNS name
				if length > 0 {
					dns := string(data[pos : pos+length])
					addresses = append(addresses, dns)
				}
			}
			pos += length
		}
		result.NetworkAddresses = addresses
	}

	return nil
}

// parsePascalString parses a Pascal-style string (length-prefixed)
func parsePascalString(data []byte, offset int) (string, error) {
	if offset >= len(data) {
		return "", fmt.Errorf("offset beyond data")
	}

	length := int(data[offset])
	if offset+1+length > len(data) {
		return "", fmt.Errorf("string extends beyond data")
	}

	str := string(data[offset+1 : offset+1+length])
	return str, nil
}

// parseUTF16String parses a UTF-16 string with 2-byte length prefix
func parseUTF16String(data []byte, offset int) (string, error) {
	if offset+1 >= len(data) {
		return "", fmt.Errorf("offset beyond data")
	}

	length := binary.BigEndian.Uint16(data[offset : offset+2])
	if offset+2+int(length) > len(data) {
		return "", fmt.Errorf("string extends beyond data")
	}

	str := string(data[offset+2 : offset+2+int(length)])
	return str, nil
}

// buildDSICommandRequest builds a DSI command request
func buildDSICommandRequest(data []byte) []byte {
	dataLength := len(data)

	// DSI Header: flags(1) + command(1) + requestID(2) + errorCode(4) + dataLength(4) + reserved(4)
	request := []byte{
		DSI_REQUEST, // Flags: request
		DSI_COMMAND, // Command: Command
		0x00, 0x01,  // Request ID: 1
		0x00, 0x00, 0x00, 0x00, // Error code: 0
		byte(dataLength >> 24), byte(dataLength >> 16), byte(dataLength >> 8), byte(dataLength), // Data length
		0x00, 0x00, 0x00, 0x00, // Reserved
	}

	return append(request, data...)
}

// fpGetSrvrParms performs FPGetSrvrParms to list shares
func fpGetSrvrParms(conn net.Conn) ([]string, error) {
	// Build FPGetSrvrParms command
	data := []byte{
		FP_GET_SRV_PARMS, // Command
		0x00,             // Padding
	}

	request := buildDSICommandRequest(data)

	_, err := conn.Write(request)
	if err != nil {
		return nil, fmt.Errorf("write failed: %v", err)
	}

	// Read response
	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil {
		return nil, fmt.Errorf("read failed: %v", err)
	}

	if n < 16 {
		return nil, fmt.Errorf("response too short")
	}

	// Parse DSI header
	if response[0] != DSI_RESPONSE || response[1] != DSI_COMMAND {
		return nil, fmt.Errorf("invalid DSI response")
	}

	errorCode := binary.BigEndian.Uint32(response[4:8])
	if errorCode != 0 {
		return nil, fmt.Errorf("AFP error: %d", errorCode)
	}

	dataLength := binary.BigEndian.Uint32(response[8:12])
	if dataLength == 0 || n < 16 {
		return []string{}, nil
	}

	respData := response[16 : 16+dataLength]
	if len(respData) < 5 {
		return nil, fmt.Errorf("insufficient data")
	}

	// Parse server time and volume count
	pos := 4 // Skip server time
	volCount := int(respData[pos])
	pos++

	// Parse volume names
	var volumes []string
	for i := 0; i < volCount && pos < len(respData); i++ {
		if pos >= len(respData) {
			break
		}
		// Skip volume bitmap
		pos++
		if pos >= len(respData) {
			break
		}

		// Parse volume name (Pascal string)
		nameLength := int(respData[pos])
		pos++
		if pos+nameLength > len(respData) {
			break
		}

		volumeName := string(respData[pos : pos+nameLength])
		volumes = append(volumes, volumeName)
		pos += nameLength
	}

	return volumes, nil
}

// fpOpenVol performs FPOpenVol to open a volume
func fpOpenVol(conn net.Conn, volumeName string) (uint16, error) {
	// Build FPOpenVol command with volume bitmap ID
	volumeBytes := append([]byte{byte(len(volumeName))}, []byte(volumeName)...)

	data := []byte{
		FP_OPEN_VOL, // Command
		0x00,        // Padding
	}

	// Volume bitmap (ID only)
	data = append(data, 0x00, 0x20) // VOL_BITMAP_ID
	// Volume name
	data = append(data, volumeBytes...)

	request := buildDSICommandRequest(data)

	_, err := conn.Write(request)
	if err != nil {
		return 0, fmt.Errorf("write failed: %v", err)
	}

	// Read response
	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil {
		return 0, fmt.Errorf("read failed: %v", err)
	}

	if n < 16 {
		return 0, fmt.Errorf("response too short")
	}

	// Parse DSI header
	if response[0] != DSI_RESPONSE || response[1] != DSI_COMMAND {
		return 0, fmt.Errorf("invalid DSI response")
	}

	errorCode := binary.BigEndian.Uint32(response[4:8])
	if errorCode != 0 {
		return 0, fmt.Errorf("AFP error: %d", errorCode)
	}

	dataLength := binary.BigEndian.Uint32(response[8:12])
	if dataLength < 4 || n < 16+4 {
		return 0, fmt.Errorf("insufficient response data")
	}

	respData := response[16 : 16+dataLength]

	// Parse volume bitmap and volume ID
	_ = binary.BigEndian.Uint16(respData[0:2]) // volumeBitmap (unused)
	volumeID := binary.BigEndian.Uint16(respData[2:4])

	return volumeID, nil
}

// fpGetFileDirParams performs FPGetFileDirParams to get directory permissions
func fpGetFileDirParams(conn net.Conn, volumeID uint16, dirID uint32) (uint32, error) {
	// Build FPGetFileDirParams command for root directory (dirID = 2)
	data := []byte{
		FP_GET_FILE_DIR_PARAMS, // Command
		0x00,                   // Padding
	}

	// Volume ID
	data = append(data,
		byte(volumeID>>8), byte(volumeID))

	// Directory ID (root directory = 2)
	data = append(data,
		byte(dirID>>24), byte(dirID>>16), byte(dirID>>8), byte(dirID))

	// File bitmap (0)
	data = append(data, 0x00, 0x00)

	// Directory bitmap (ACCESS_RIGHTS)
	data = append(data,
		byte(DIR_BITMAP_ACCESS_RIGHTS>>8), byte(DIR_BITMAP_ACCESS_RIGHTS&0xFF))

	// Path (empty for root directory)
	data = append(data,
		0x02, // PATH_TYPE.LongName
		0x00) // Empty name

	request := buildDSICommandRequest(data)

	_, err := conn.Write(request)
	if err != nil {
		return 0, fmt.Errorf("write failed: %v", err)
	}

	// Read response
	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil {
		return 0, fmt.Errorf("read failed: %v", err)
	}

	if n < 16 {
		return 0, fmt.Errorf("response too short")
	}

	// Parse DSI header
	if response[0] != DSI_RESPONSE || response[1] != DSI_COMMAND {
		return 0, fmt.Errorf("invalid DSI response")
	}

	errorCode := binary.BigEndian.Uint32(response[4:8])
	if errorCode != 0 {
		return 0, fmt.Errorf("AFP error: %d", errorCode)
	}

	dataLength := binary.BigEndian.Uint32(response[8:12])
	if dataLength < 8 || n < 16+8 {
		return 0, fmt.Errorf("insufficient response data")
	}

	respData := response[16 : 16+dataLength]

	// Parse file bitmap, dir bitmap, and file type
	pos := 0
	_ = binary.BigEndian.Uint16(respData[pos : pos+2]) // fileBitmap (unused)
	pos += 2
	dirBitmap := binary.BigEndian.Uint16(respData[pos : pos+2])
	pos += 2
	fileType := respData[pos]
	pos += 1 // Skip padding

	// Check if it's a directory
	if fileType != 0x80 {
		return 0, fmt.Errorf("not a directory")
	}

	// Parse directory bitmap to get access rights
	if (dirBitmap&DIR_BITMAP_ACCESS_RIGHTS) != 0 && pos+4 <= len(respData) {
		accessRights := binary.BigEndian.Uint32(respData[pos : pos+4])
		return accessRights, nil
	}

	return 0, fmt.Errorf("access rights not found")
}

// fpCloseVol performs FPCloseVol to close a volume
func fpCloseVol(conn net.Conn, volumeID uint16) error {
	// Build FPCloseVol command
	data := []byte{
		FP_CLOSE_VOL, // Command
		0x00,         // Padding
	}

	// Volume ID
	data = append(data,
		byte(volumeID>>8), byte(volumeID))

	request := buildDSICommandRequest(data)

	_, err := conn.Write(request)
	if err != nil {
		return fmt.Errorf("write failed: %v", err)
	}

	// Read response
	response := make([]byte, 16)
	n, err := conn.Read(response)
	if err != nil {
		return fmt.Errorf("read failed: %v", err)
	}

	if n < 16 {
		return fmt.Errorf("response too short")
	}

	// Parse DSI header
	if response[0] != DSI_RESPONSE || response[1] != DSI_COMMAND {
		return fmt.Errorf("invalid DSI response")
	}

	errorCode := binary.BigEndian.Uint32(response[4:8])
	if errorCode != 0 {
		return fmt.Errorf("AFP error: %d", errorCode)
	}

	return nil
}

// parseACLs converts ACL bitmask to readable format
func parseACLs(acl uint32) AFPShareInfo {
	var share AFPShareInfo

	// Owner permissions (bits 0-8)
	ownerPerms := acl & 0xFF
	if ownerPerms&ACL_OWNER_SEARCH != 0 {
		share.OwnerPermissions = append(share.OwnerPermissions, "Search")
	}
	if ownerPerms&ACL_OWNER_READ != 0 {
		share.OwnerPermissions = append(share.OwnerPermissions, "Read")
	}
	if ownerPerms&ACL_OWNER_WRITE != 0 {
		share.OwnerPermissions = append(share.OwnerPermissions, "Write")
	}

	// Group permissions (bits 8-16)
	groupPerms := (acl >> 8) & 0xFF
	if groupPerms&ACL_GROUP_SEARCH != 0 {
		share.GroupPermissions = append(share.GroupPermissions, "Search")
	}
	if groupPerms&ACL_GROUP_READ != 0 {
		share.GroupPermissions = append(share.GroupPermissions, "Read")
	}
	if groupPerms&ACL_GROUP_WRITE != 0 {
		share.GroupPermissions = append(share.GroupPermissions, "Write")
	}

	// Everyone permissions (bits 16-24)
	everyonePerms := (acl >> 16) & 0xFF
	if everyonePerms&ACL_EVERYONE_SEARCH != 0 {
		share.EveryonePermissions = append(share.EveryonePermissions, "Search")
	}
	if everyonePerms&ACL_EVERYONE_READ != 0 {
		share.EveryonePermissions = append(share.EveryonePermissions, "Read")
	}
	if everyonePerms&ACL_EVERYONE_WRITE != 0 {
		share.EveryonePermissions = append(share.EveryonePermissions, "Write")
	}

	// User permissions (bits 24-32)
	userPerms := (acl >> 24) & 0xFF
	if userPerms&ACL_USER_SEARCH != 0 {
		share.UserPermissions = append(share.UserPermissions, "Search")
	}
	if userPerms&ACL_USER_READ != 0 {
		share.UserPermissions = append(share.UserPermissions, "Read")
	}
	if userPerms&ACL_USER_WRITE != 0 {
		share.UserPermissions = append(share.UserPermissions, "Write")
	}

	// Options
	if acl&ACL_BLANK_ACCESS != 0 {
		share.Options = append(share.Options, "Blank")
	}
	if acl&ACL_USER_IS_OWNER != 0 {
		share.Options = append(share.Options, "IsOwner")
	}

	return share
}

// getAFPShares gets share listing with permissions
func getAFPShares(ip string, port int, timeout time.Duration) ([]AFPShareInfo, error) {
	conn, err := helpers.DialTCP(ip, port, timeout)
	if err != nil {
		return nil, fmt.Errorf("connection failed: %v", err)
	}
	defer conn.Close()

	// Get list of shares
	volumes, err := fpGetSrvrParms(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to get shares: %v", err)
	}
	var shares []AFPShareInfo

	// Get permissions for each share
	for _, volumeName := range volumes {
		// Open volume
		volumeID, err := fpOpenVol(conn, volumeName)
		if err != nil {
			// Skip this volume if we can't open it
			continue
		}

		// Get directory permissions for root directory
		accessRights, err := fpGetFileDirParams(conn, volumeID, 2) // dirID 2 = root directory
		if err == nil {
			share := parseACLs(accessRights)
			share.Name = volumeName
			shares = append(shares, share)
		}

		// Close volume
		fpCloseVol(conn, volumeID)
	}

	return shares, nil
}
