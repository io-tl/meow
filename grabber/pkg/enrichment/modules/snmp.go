package modules

import (
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"

	"meow/grabber/pkg/enrichment/modules/helpers"
)

// SNMPModule implements the SNMP enrichment module
type SNMPModule struct {
	BaseModule
}

// SNMPResult represents the enriched SNMP data
type SNMPResult struct {
	Protocol       string          `json:"protocol"`
	Version        string          `json:"version,omitempty"`           // v1, v2c, v3
	Community      string          `json:"community,omitempty"`         // Community string (if public works)
	SysDescr       string          `json:"sys_descr,omitempty"`         // System description (1.3.6.1.2.1.1.1.0)
	SysObjectID    string          `json:"sys_object_id,omitempty"`     // System OID (1.3.6.1.2.1.1.2.0)
	SysUpTime      string          `json:"sys_uptime,omitempty"`        // System uptime (1.3.6.1.2.1.1.3.0)
	SysContact     string          `json:"sys_contact,omitempty"`       // System contact (1.3.6.1.2.1.1.4.0)
	SysName        string          `json:"sys_name,omitempty"`          // System name (1.3.6.1.2.1.1.5.0)
	SysLocation    string          `json:"sys_location,omitempty"`      // System location (1.3.6.1.2.1.1.6.0)
	SysServices    string          `json:"sys_services,omitempty"`      // System services (1.3.6.1.2.1.1.7.0)
	Hostname       string          `json:"hostname,omitempty"`          // Hostname
	Domain         string          `json:"domain,omitempty"`            // Domain name
	Interfaces     []SNMPInterface `json:"interfaces,omitempty"`        // Network interfaces
	IfNumber       int             `json:"if_number,omitempty"`         // Number of interfaces (1.3.6.1.2.1.2.1.0)
	HrSystemUptime string          `json:"hr_system_uptime,omitempty"`  // Host Resources uptime (1.3.6.1.2.1.25.1.1.0)
	HrSystemDate   string          `json:"hr_system_date,omitempty"`    // Host Resources system date (1.3.6.1.2.1.25.1.2.0)
	HrSystemUsers  int             `json:"hr_system_users,omitempty"`   // Number of logged users (1.3.6.1.2.1.25.1.5.0)
	HrSystemProcs  int             `json:"hr_system_procs,omitempty"`   // Number of processes (1.3.6.1.2.1.25.1.6.0)
	HrMemorySize   int             `json:"hr_memory_size,omitempty"`    // Memory size in KB (1.3.6.1.2.1.25.2.2.0)
	WindowsDomain  string          `json:"windows_domain,omitempty"`    // Windows domain (1.3.6.1.4.1.77.1.4.1.0)
	WindowsUsers   []string        `json:"windows_users,omitempty"`     // Windows users
	Communities    []string        `json:"communities_found,omitempty"` // All valid communities found
	Error          string          `json:"error,omitempty"`
}

// SNMPInterface represents a network interface
type SNMPInterface struct {
	Index       int    `json:"index"`
	Description string `json:"description"`
	Type        string `json:"type"`
	MTU         int    `json:"mtu"`
	Speed       int    `json:"speed"`
	PhysAddr    string `json:"phys_addr"`
	AdminStatus string `json:"admin_status"`
	OperStatus  string `json:"oper_status"`
	IPAddress   string `json:"ip_address,omitempty"`
}

func init() {
	Register(&SNMPModule{
		BaseModule: NewBaseModule(
			"snmp",
			[]string{},
			true, // Should enrich
			15*time.Second,
		),
	})
}

func (m *SNMPModule) Scan(ip string, port int) (interface{}, error) {
	return scanSNMP(ip, port, m.DefaultTimeout())
}

// Common community strings to try (ordered by probability)
var commonCommunities = []string{
	"public",
	"private",
	"community",
	"snmp",
	"monitor",
	"read",
	"write",
}

// Extended community strings (only tested if configured)
var extendedCommunities = []string{
	"manager",
	"admin",
	"administrator",
	"root",
	"password",
	"default",
	"cisco",
	"secret",
	"security",
	"test",
	"guest",
	"rmon",
	"mngt",
	"ILMI",
	"netman",
	"network",
	"agent",
	"switch",
	"router",
	"enable",
	"pass",
	"system",
	"user",
	"all",
}

// Important OIDs to query
type snmpOID struct {
	oid  string
	name string
}

var systemOIDs = []snmpOID{
	{"1.3.6.1.2.1.1.1.0", "sysDescr"},
	{"1.3.6.1.2.1.1.2.0", "sysObjectID"},
	{"1.3.6.1.2.1.1.3.0", "sysUpTime"},
	{"1.3.6.1.2.1.1.4.0", "sysContact"},
	{"1.3.6.1.2.1.1.5.0", "sysName"},
	{"1.3.6.1.2.1.1.6.0", "sysLocation"},
	{"1.3.6.1.2.1.1.7.0", "sysServices"},
	{"1.3.6.1.2.1.2.1.0", "ifNumber"},
	{"1.3.6.1.2.1.25.1.1.0", "hrSystemUptime"},
	{"1.3.6.1.2.1.25.1.2.0", "hrSystemDate"},
	{"1.3.6.1.2.1.25.1.5.0", "hrSystemUsers"},
	{"1.3.6.1.2.1.25.1.6.0", "hrSystemProcs"},
	{"1.3.6.1.2.1.25.2.2.0", "hrMemorySize"},
	{"1.3.6.1.4.1.77.1.4.1.0", "svSvcName"}, // Windows domain
}

// scanSNMP performs comprehensive SNMP enrichment
func scanSNMP(ip string, port int, timeout time.Duration) (*SNMPResult, error) {
	result := &SNMPResult{
		Protocol:    "snmp",
		Communities: []string{},
	}

	// Try SNMPv2c first (most common), then v1 with different communities
	foundCommunity := false
	testTimeout := 500 * time.Millisecond // Quick timeout for community testing

	for _, community := range commonCommunities {
		// Test v2c first (most common)
		if testSNMPCommunity(ip, port, community, 1, result, testTimeout) {
			result.Communities = append(result.Communities, community)
			if result.Version == "" {
				result.Version = "v2c"
			}
			foundCommunity = true
			break // Stop at first valid community for speed
		} else if testSNMPCommunity(ip, port, community, 0, result, testTimeout) {
			// Try v1 if v2c failed
			result.Communities = append(result.Communities, community)
			if result.Version == "" {
				result.Version = "v1"
			}
			foundCommunity = true
			break // Stop at first valid community
		}
	}

	// If at least one community worked, gather full information
	if foundCommunity && len(result.Communities) > 0 {
		result.Community = result.Communities[0]
		// Get comprehensive system information
		version := 1
		if result.Version == "v1" {
			version = 0
		}
		getAllSNMPInfo(ip, port, result.Community, version, result, timeout)
	} else {
		// Try SNMPv3 (no community)
		if trySNMPv3(ip, port, result, timeout) {
			result.Version = "v3"
		} else {
			result.Error = "No valid community string found"
		}
	}

	return result, nil
}

// testSNMPCommunity tests a specific community string with a specific version
func testSNMPCommunity(ip string, port int, community string, version int, result *SNMPResult, timeout time.Duration) bool {
	addr := fmt.Sprintf("%s:%d", ip, port)
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return false
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return false
	}
	defer conn.Close()

	// Query sysDescr to test if community is valid
	packet := buildSNMPGetRequest(community, "1.3.6.1.2.1.1.1.0", version)

	conn.SetWriteDeadline(time.Now().Add(timeout))
	_, err = conn.Write(packet)
	if err != nil {
		return false
	}

	conn.SetReadDeadline(time.Now().Add(timeout))
	response := make([]byte, 4096)
	n, err := conn.Read(response)
	if err != nil {
		return false
	}

	if n > 0 {
		value, err := parseSNMPResponse(response[:n])
		if err == nil && value != "" {
			if result.SysDescr == "" {
				result.SysDescr = value
			}
			return true
		}
	}

	return false
}

// getAllSNMPInfo retrieves all SNMP information with a single connection approach
func getAllSNMPInfo(ip string, port int, community string, version int, result *SNMPResult, timeout time.Duration) {
	// Get system information
	conn, err := helpers.DialUDP(ip, port, timeout)
	if err != nil {
		return
	}
	defer conn.Close()

	getSNMPSystemInfo(conn, community, result, timeout)
	getInterfaceInfo(conn, community, result, timeout)
}

// buildSNMPGetRequest builds an SNMP GetRequest for v1 or v2c
func buildSNMPGetRequest(community string, oid string, version int) []byte {
	// Parse OID string to []int
	oidInts := parseOID(oid)

	// Encode OID
	encodedOID := encodeOID(oidInts)

	// Build VarBind: SEQUENCE { OID, NULL }
	nullValue := []byte{0x05, 0x00}
	varBind := buildSequence(append(encodedOID, nullValue...))

	// Build VarBindList: SEQUENCE of VarBind
	varBindList := buildSequence(varBind)

	// Build PDU: GetRequest (0xa0)
	requestID := []byte{0x02, 0x04, 0x00, 0x00, 0x00, 0x01} // Request ID = 1
	errorStatus := []byte{0x02, 0x01, 0x00}                 // Error Status = 0
	errorIndex := []byte{0x02, 0x01, 0x00}                  // Error Index = 0

	pduData := append(requestID, errorStatus...)
	pduData = append(pduData, errorIndex...)
	pduData = append(pduData, varBindList...)

	pdu := buildTLV(0xa0, pduData)

	// Encode community string
	communityBytes := []byte(community)
	encodedCommunity := buildTLV(0x04, communityBytes)

	// Encode version (0 = v1, 1 = v2c)
	encodedVersion := []byte{0x02, 0x01, byte(version)}

	// Build message: SEQUENCE { version, community, PDU }
	msgData := append(encodedVersion, encodedCommunity...)
	msgData = append(msgData, pdu...)

	message := buildSequence(msgData)

	return message
}

// buildSequence creates a SEQUENCE TLV
func buildSequence(data []byte) []byte {
	return buildTLV(0x30, data)
}

// buildTLV creates a Tag-Length-Value structure
func buildTLV(tag byte, data []byte) []byte {
	length := len(data)
	if length < 128 {
		return append([]byte{tag, byte(length)}, data...)
	}
	// Long form length (for lengths >= 128)
	if length < 256 {
		return append([]byte{tag, 0x81, byte(length)}, data...)
	}
	// Very long form (for lengths >= 256)
	return append([]byte{tag, 0x82, byte(length >> 8), byte(length & 0xff)}, data...)
}

// parseOID converts OID string to []int
func parseOID(oid string) []int {
	parts := strings.Split(oid, ".")
	result := make([]int, len(parts))
	for i, part := range parts {
		fmt.Sscanf(part, "%d", &result[i])
	}
	return result
}

// encodeOID encodes OID as ASN.1
func encodeOID(oid []int) []byte {
	if len(oid) < 2 {
		return []byte{0x06, 0x00}
	}

	// First byte encodes first two numbers: 40*first + second
	encoded := []byte{byte(40*oid[0] + oid[1])}

	// Encode remaining numbers
	for i := 2; i < len(oid); i++ {
		encoded = append(encoded, encodeOIDValue(oid[i])...)
	}

	return append([]byte{0x06, byte(len(encoded))}, encoded...)
}

// encodeOIDValue encodes a single OID value
func encodeOIDValue(value int) []byte {
	if value < 128 {
		return []byte{byte(value)}
	}

	var result []byte
	for value > 0 {
		result = append([]byte{byte(value&0x7f) | 0x80}, result...)
		value >>= 7
	}
	result[len(result)-1] &= 0x7f
	return result
}

// parseSNMPResponse parses SNMP response using ASN.1
func parseSNMPResponse(response []byte) (string, error) {
	if len(response) < 10 {
		return "", fmt.Errorf("response too short")
	}

	// Parse outer SEQUENCE
	if response[0] != 0x30 {
		return "", fmt.Errorf("not a SEQUENCE")
	}

	// Skip to PDU (look for GetResponse 0xa2)
	var pduStart int
	for i := 2; i < len(response)-2; i++ {
		if response[i] == 0xa2 {
			pduStart = i
			break
		}
	}

	if pduStart == 0 {
		return "", fmt.Errorf("PDU not found")
	}

	// Look for VarBindList (SEQUENCE 0x30) inside the PDU
	// Skip requestID, errorStatus, errorIndex to find VarBindList
	varBindStart := 0
	seqCount := 0
	for i := pduStart + 2; i < len(response)-2; i++ {
		if response[i] == 0x30 {
			seqCount++
			if seqCount == 1 { // This should be the VarBindList
				varBindStart = i
				break
			}
		}
	}

	if varBindStart == 0 {
		return "", fmt.Errorf("VarBindList not found")
	}

	// Now search from VarBindList for the value (skip the OID first)
	skipOID := false
	for i := varBindStart + 2; i < len(response)-2; i++ {
		tag := response[i]

		// Skip OID if we encounter it
		if tag == 0x06 && !skipOID {
			length := int(response[i+1])
			if length&0x80 != 0 {
				numOctets := length & 0x7f
				length = 0
				for j := 0; j < numOctets && i+2+j < len(response); j++ {
					length = (length << 8) | int(response[i+2+j])
				}
				i += numOctets
			}
			if length > 0 && i+2+length <= len(response) {
				i += length + 1 // Skip OID
				skipOID = true
			}
			continue
		}

		length := int(response[i+1])

		// Handle long form length
		if length&0x80 != 0 {
			numOctets := length & 0x7f
			if i+1+numOctets >= len(response) {
				continue
			}
			length = 0
			for j := 0; j < numOctets; j++ {
				length = (length << 8) | int(response[i+2+j])
			}
			i += numOctets
		}

		if length <= 0 || i+2+length > len(response) {
			continue
		}

		switch tag {
		case 0x04: // OCTET STRING - this is what we want!
			if length > 0 && length < 500 {
				value := string(response[i+2 : i+2+length])
				if len(value) > 0 {
					return value, nil
				}
			}
		case 0x02: // INTEGER
			if skipOID && length > 0 && length <= 8 {
				var intVal int64
				for j := 0; j < length; j++ {
					intVal = (intVal << 8) | int64(response[i+2+j])
				}
				return fmt.Sprintf("%d", intVal), nil
			}
		case 0x43: // TimeTicks
			if skipOID && length == 4 {
				ticks := int(response[i+2])<<24 | int(response[i+3])<<16 | int(response[i+4])<<8 | int(response[i+5])
				return fmt.Sprintf("%d ticks", ticks), nil
			}
		case 0x41: // Counter32
			if skipOID && length > 0 && length <= 8 {
				var intVal int64
				for j := 0; j < length; j++ {
					intVal = (intVal << 8) | int64(response[i+2+j])
				}
				return fmt.Sprintf("%d", intVal), nil
			}
		case 0x42: // Gauge32
			if skipOID && length > 0 && length <= 8 {
				var intVal int64
				for j := 0; j < length; j++ {
					intVal = (intVal << 8) | int64(response[i+2+j])
				}
				return fmt.Sprintf("%d", intVal), nil
			}
		}
	}

	return "", fmt.Errorf("no value found")
}

// decodeOID decodes ASN.1 OID to string
func decodeOID(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	// First byte encodes first two numbers
	oid := fmt.Sprintf("%d.%d", data[0]/40, data[0]%40)

	// Decode remaining numbers
	i := 1
	for i < len(data) {
		value := 0
		for i < len(data) && data[i]&0x80 != 0 {
			value = (value << 7) | int(data[i]&0x7f)
			i++
		}
		if i < len(data) {
			value = (value << 7) | int(data[i])
			i++
		}
		oid += fmt.Sprintf(".%d", value)
	}

	return oid
}

// getSNMPSystemInfo retrieves comprehensive system information
func getSNMPSystemInfo(conn net.Conn, community string, result *SNMPResult, timeout time.Duration) {
	// Determine which version to use based on result
	version := 1 // Default to v2c
	if result.Version == "v1" {
		version = 0
	}

	queryTimeout := 500 * time.Millisecond // Quick timeout for queries

	// Query all system OIDs
	for _, sysOID := range systemOIDs {
		if sysOID.name == "sysDescr" && result.SysDescr != "" {
			continue // Already have this
		}

		packet := buildSNMPGetRequest(community, sysOID.oid, version)

		conn.SetWriteDeadline(time.Now().Add(queryTimeout))
		_, err := conn.Write(packet)
		if err != nil {
			continue
		}

		conn.SetReadDeadline(time.Now().Add(queryTimeout))
		response := make([]byte, 4096)
		n, err := conn.Read(response)
		if err != nil {
			continue
		}

		if n > 0 {
			value, err := parseSNMPResponse(response[:n])
			if err == nil && value != "" {
				// Map value to result field
				switch sysOID.name {
				case "sysDescr":
					result.SysDescr = value
				case "sysObjectID":
					result.SysObjectID = value
				case "sysUpTime":
					result.SysUpTime = value
				case "sysContact":
					result.SysContact = value
				case "sysName":
					result.SysName = value
					result.Hostname = value
				case "sysLocation":
					result.SysLocation = value
				case "sysServices":
					result.SysServices = value
				case "ifNumber":
					fmt.Sscanf(value, "%d", &result.IfNumber)
				case "hrSystemUptime":
					result.HrSystemUptime = value
				case "hrSystemDate":
					result.HrSystemDate = value
				case "hrSystemUsers":
					fmt.Sscanf(value, "%d", &result.HrSystemUsers)
				case "hrSystemProcs":
					fmt.Sscanf(value, "%d", &result.HrSystemProcs)
				case "hrMemorySize":
					fmt.Sscanf(value, "%d", &result.HrMemorySize)
				case "svSvcName":
					result.WindowsDomain = value
				}
			}
		}

		// Small delay between requests
		time.Sleep(20 * time.Millisecond)
	}
}

// getInterfaceInfo retrieves network interface information
func getInterfaceInfo(conn net.Conn, community string, result *SNMPResult, timeout time.Duration) {
	if result.IfNumber <= 0 || result.IfNumber > 50 {
		return // Skip if no interfaces or too many
	}

	version := 1
	if result.Version == "v1" {
		version = 0
	}

	queryTimeout := 300 * time.Millisecond // Quick timeout for interface queries

	// Interface OID prefixes
	ifDescr := "1.3.6.1.2.1.2.2.1.2"      // ifDescr
	ifType := "1.3.6.1.2.1.2.2.1.3"       // ifType
	ifOperStatus := "1.3.6.1.2.1.2.2.1.8" // ifOperStatus

	// Query first few interfaces only (limit to 3 for performance)
	maxInterfaces := result.IfNumber
	if maxInterfaces > 3 {
		maxInterfaces = 3
	}

	for i := 1; i <= maxInterfaces; i++ {
		iface := SNMPInterface{Index: i}

		// Get only essential info: ifDescr, ifType, ifOperStatus
		if value := querySNMPOID(conn, community, fmt.Sprintf("%s.%d", ifDescr, i), version, queryTimeout); value != "" {
			iface.Description = value
		}

		if value := querySNMPOID(conn, community, fmt.Sprintf("%s.%d", ifType, i), version, queryTimeout); value != "" {
			iface.Type = value
		}

		if value := querySNMPOID(conn, community, fmt.Sprintf("%s.%d", ifOperStatus, i), version, queryTimeout); value != "" {
			iface.OperStatus = formatIfStatus(value)
		}

		if iface.Description != "" {
			result.Interfaces = append(result.Interfaces, iface)
		}

		time.Sleep(10 * time.Millisecond)
	}
}

// querySNMPOID queries a single OID and returns the value
func querySNMPOID(conn net.Conn, community string, oid string, version int, timeout time.Duration) string {
	packet := buildSNMPGetRequest(community, oid, version)

	conn.SetWriteDeadline(time.Now().Add(timeout))
	_, err := conn.Write(packet)
	if err != nil {
		return ""
	}

	conn.SetReadDeadline(time.Now().Add(timeout))
	response := make([]byte, 4096)
	n, err := conn.Read(response)
	if err != nil {
		return ""
	}

	if n > 0 {
		value, err := parseSNMPResponse(response[:n])
		if err == nil {
			return value
		}
	}

	return ""
}

// formatMACAddress formats MAC address bytes to string
func formatMACAddress(mac []byte) string {
	if len(mac) != 6 {
		return ""
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

// formatIfStatus converts interface status integer to string
func formatIfStatus(status string) string {
	var statusInt int
	fmt.Sscanf(status, "%d", &statusInt)
	switch statusInt {
	case 1:
		return "up"
	case 2:
		return "down"
	case 3:
		return "testing"
	default:
		return "unknown"
	}
}

// trySNMPv3 attempts SNMPv3 discovery (no auth)
func trySNMPv3(ip string, port int, result *SNMPResult, timeout time.Duration) bool {
	conn, err := helpers.DialUDP(ip, port, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()

	// Build SNMPv3 discovery message (RFC 3414)
	// This is a simplified version - full SNMPv3 requires much more complex handling
	packet := buildSNMPv3Discovery()

	conn.SetWriteDeadline(time.Now().Add(timeout))
	_, err = conn.Write(packet)
	if err != nil {
		return false
	}

	conn.SetReadDeadline(time.Now().Add(timeout))
	response := make([]byte, 4096)
	n, err := conn.Read(response)
	if err != nil {
		return false
	}

	// If we get any response, SNMPv3 is present
	if n > 0 && response[0] == 0x30 {
		result.Version = "v3"
		// Try to parse engine ID from response
		engineID := extractSNMPv3EngineID(response[:n])
		if engineID != "" {
			result.SysObjectID = engineID
		}
		return true
	}

	return false
}

// buildSNMPv3Discovery builds an SNMPv3 discovery message
func buildSNMPv3Discovery() []byte {
	// Simplified SNMPv3 discovery packet (no auth, no priv)
	// This would need to be much more complex for full SNMPv3 support
	discovery, _ := hex.DecodeString(
		"3081" + // SEQUENCE
			"80" + // Length (long form)
			"0201" + // Version (SNMPv3 = 3)
			"03" +
			"3011" + // HeaderData
			"0208" + // msgID
			"00000001" +
			"020400" + // msgMaxSize
			"00ffff" +
			"0401" + // msgFlags (noAuthNoPriv)
			"00" +
			"0201" + // msgSecurityModel
			"03" +
			"3000" + // msgSecurityParameters (empty)
			"3053" + // ScopedPDU
			"0400" + // contextEngineID (empty for discovery)
			"0400" + // contextName (empty)
			"a046" + // PDU (GetRequest)
			"0204" + // requestID
			"00000001" +
			"0201" + // errorStatus
			"00" +
			"0201" + // errorIndex
			"00" +
			"3038" + // VarBindList
			"3036" + // VarBind
			"0608" + // OID for sysDescr
			"2b060102010101" +
			"00" + // instance
			"0500", // NULL
	)
	return discovery
}

// extractSNMPv3EngineID extracts engine ID from SNMPv3 response
func extractSNMPv3EngineID(response []byte) string {
	// Look for OCTET STRING that contains engine ID
	// This is a simplified extraction
	for i := 0; i < len(response)-10; i++ {
		if response[i] == 0x04 && response[i+1] > 5 && response[i+1] < 50 {
			length := int(response[i+1])
			if i+2+length <= len(response) {
				engineID := response[i+2 : i+2+length]
				return hex.EncodeToString(engineID)
			}
		}
	}
	return ""
}
