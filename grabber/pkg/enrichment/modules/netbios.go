package modules

import (
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"

	"meow/grabber/pkg/enrichment/modules/helpers"
)

// NetBIOSModule implements the NetBIOS enrichment module
type NetBIOSModule struct {
	BaseModule
}

// NetBIOSResult represents the enriched NetBIOS data
type NetBIOSResult struct {
	Protocol      string        `json:"protocol"`
	NetBIOSName   string        `json:"netbios_name,omitempty"`   // Computer name
	NetBIOSUser   string        `json:"netbios_user,omitempty"`   // Logged in user
	NetBIOSDomain string        `json:"netbios_domain,omitempty"` // Domain/Workgroup
	MACAddress    string        `json:"mac_address,omitempty"`
	MACVendor     string        `json:"mac_vendor,omitempty"`
	Names         []NetBIOSName `json:"names,omitempty"`
	Error         string        `json:"error,omitempty"`
}

// NetBIOSName represents a NetBIOS name entry
type NetBIOSName struct {
	Name    string   `json:"name"`
	Suffix  string   `json:"suffix"`          // Hex suffix like <00>, <20>, etc.
	Service string   `json:"service"`         // Human-readable service type
	Flags   []string `json:"flags,omitempty"` // group/unique, active/deregistering
}

// NetBIOSNSModule implements the NetBIOS Name Service (UDP) module
type NetBIOSNSModule struct {
	BaseModule
}

func init() {
	Register(&NetBIOSModule{
		BaseModule: NewBaseModule(
			"netbios-ssn",
			[]string{"netbios"},
			true, // Should enrich
			10*time.Second,
		),
	})

	Register(&NetBIOSNSModule{
		BaseModule: NewBaseModule(
			"netbios-ns",
			[]string{},
			true, // Should enrich
			10*time.Second,
		),
	})
}

func (m *NetBIOSNSModule) Scan(ip string, port int) (interface{}, error) {
	return scanNetBIOSNameService(ip, m.DefaultTimeout())
}

func (m *NetBIOSModule) Scan(ip string, port int) (interface{}, error) {
	return scanNetBIOS(ip, port, m.DefaultTimeout())
}

// scanNetBIOS performs NetBIOS enrichment
func scanNetBIOS(ip string, port int, timeout time.Duration) (*NetBIOSResult, error) {
	result := &NetBIOSResult{
		Protocol: "netbios",
	}

	// Always try NetBIOS Name Service query (UDP port 137) to get names
	// This works for both port 137 and 139
	nameResult, err := scanNetBIOSNameService(ip, timeout)
	if err == nil && nameResult != nil {
		// Use the result from name service
		result = nameResult
	}

	// If port is 137, we're done (UDP Name Service only)
	if port == 137 {
		return result, err
	}

	// For TCP port 139 (NetBIOS Session Service), also try session connection
	conn, err := helpers.DialTCP(ip, port, timeout)
	if err != nil {
		// If we got names from UDP 137, still return them even if TCP fails
		if len(result.Names) > 0 {
			return result, nil
		}
		result.Error = err.Error()
		return result, err
	}
	defer conn.Close()

	// Build NetBIOS Session Request
	sessionRequest := buildNetBIOSSessionRequest()

	_, err = conn.Write(sessionRequest)
	if err != nil {
		// If we got names from UDP 137, still return them even if TCP fails
		if len(result.Names) > 0 {
			return result, nil
		}
		result.Error = err.Error()
		return result, err
	}

	// Read response
	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil {
		// If we got names from UDP 137, still return them even if TCP fails
		if len(result.Names) > 0 {
			return result, nil
		}
		result.Error = err.Error()
		return result, err
	}

	if n > 4 {
		// Parse NetBIOS session response
		msgType := response[0]
		if msgType == 0x82 || msgType == 0x83 {
			// Session service is available - names already populated from UDP query
			// Just confirm the session service is active
		}
	}

	return result, nil
}

// scanNetBIOSNameService performs NetBIOS Name Service query (nbtstat)
func scanNetBIOSNameService(ip string, timeout time.Duration) (*NetBIOSResult, error) {
	result := &NetBIOSResult{
		Protocol: "netbios",
	}

	// Explicitly open UDP socket on port 137 for nbtstat
	conn, err := net.DialTimeout("udp", fmt.Sprintf("%s:137", ip), timeout)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	defer conn.Close()

	// Set read deadline
	conn.SetDeadline(time.Now().Add(timeout))

	// Build NetBIOS Name Query (Node Status Request)
	query := buildNetBIOSNameQuery()

	_, err = conn.Write(query)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	// Read response
	response := make([]byte, 4096)
	n, err := conn.Read(response)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	if n > 56 {
		// Parse NetBIOS Name Query Response
		// Names start at offset 56
		numNames := int(response[56])
		offset := 57

		for i := 0; i < numNames && offset+18 <= n; i++ {
			// Each entry is 18 bytes: name (15) + suffix (1) + flags (2)
			nameBytes := response[offset : offset+15]
			suffix := response[offset+15]
			flags := uint16(response[offset+16])<<8 | uint16(response[offset+17])

			// Extract name (trimming spaces)
			name := strings.TrimSpace(string(nameBytes))

			if name != "" {
				netbiosName := NetBIOSName{
					Name:    name,
					Suffix:  fmt.Sprintf("<%02x>", suffix),
					Service: getNetBIOSServiceType(suffix),
					Flags:   parseNetBIOSFlags(flags),
				}

				result.Names = append(result.Names, netbiosName)

				// Extract specific information
				if suffix == 0x00 && !isGroupName(flags) {
					// Computer name (unique <00>)
					result.NetBIOSName = name
				} else if suffix == 0x00 && isGroupName(flags) {
					// Domain/Workgroup name (group <00>)
					result.NetBIOSDomain = name
				} else if suffix == 0x03 && !isGroupName(flags) {
					// Logged in user (unique <03>)
					result.NetBIOSUser = name
				} else if suffix == 0x1b && !isGroupName(flags) {
					// Domain Master Browser - this is the domain
					if result.NetBIOSDomain == "" {
						result.NetBIOSDomain = name
					}
				}
			}

			offset += 18
		}

		// MAC address is typically at the end of the adapter status
		// It's located after all name entries
		if n >= offset+6 {
			macBytes := response[offset : offset+6]
			result.MACAddress = fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
				macBytes[0], macBytes[1], macBytes[2], macBytes[3], macBytes[4], macBytes[5])

			// Try to identify MAC vendor
			result.MACVendor = getMACVendor(macBytes)
		}
	}

	// Set default user if not found
	if result.NetBIOSUser == "" {
		result.NetBIOSUser = "<unknown>"
	}

	return result, nil
}

// getNetBIOSServiceType returns the service type for a NetBIOS suffix
func getNetBIOSServiceType(suffix byte) string {
	services := map[byte]string{
		0x00: "Workstation Service",
		0x01: "Messenger Service",
		0x03: "Messenger Service (user)",
		0x06: "RAS Server Service",
		0x1B: "Domain Master Browser",
		0x1C: "Domain Controllers",
		0x1D: "Master Browser",
		0x1E: "Browser Service Elections",
		0x20: "File Server Service",
		0x21: "RAS Client Service",
		0x22: "Microsoft Exchange Interchange",
		0x23: "Microsoft Exchange Store",
		0x24: "Microsoft Exchange Directory",
		0x30: "Modem Sharing Server Service",
		0x31: "Modem Sharing Client Service",
		0x43: "SMS Clients Remote Control",
		0x44: "SMS Administrators Remote Control Tool",
		0x45: "SMS Clients Remote Chat",
		0x46: "SMS Clients Remote Transfer",
		0x4C: "DEC Pathworks TCPIP service on Windows NT",
		0x52: "DEC Pathworks TCPIP service on Windows NT",
		0x87: "Microsoft Exchange MTA",
		0x6A: "Microsoft Exchange IMC",
		0xBE: "Network Monitor Agent",
		0xBF: "Network Monitor Application",
	}

	if service, ok := services[suffix]; ok {
		return service
	}
	return fmt.Sprintf("Unknown service (0x%02x)", suffix)
}

// parseNetBIOSFlags parses NetBIOS name flags
func parseNetBIOSFlags(flags uint16) []string {
	var result []string

	// Check if it's a group name
	if (flags & 0x8000) != 0 {
		result = append(result, "group")
	} else {
		result = append(result, "unique")
	}

	// Check node type
	nodeType := (flags >> 13) & 0x03
	switch nodeType {
	case 0:
		// B-node
	case 1:
		// P-node
	case 2:
		// M-node
	case 3:
		// H-node (Hybrid)
	}

	// Check state
	if (flags & 0x0400) != 0 {
		result = append(result, "deregistering")
	} else if (flags & 0x0600) == 0x0000 {
		// Active (no deregistering or conflict flags set)
		result = append(result, "active")
	}

	if (flags & 0x0800) != 0 {
		result = append(result, "conflict")
	}

	return result
}

// isGroupName checks if the flags indicate a group name
func isGroupName(flags uint16) bool {
	return (flags & 0x8000) != 0
}

// getMACVendor returns the vendor name for a MAC address
func getMACVendor(mac []byte) string {
	if len(mac) < 3 {
		return ""
	}

	// Common vendors (OUI - first 3 bytes)
	oui := fmt.Sprintf("%02X%02X%02X", mac[0], mac[1], mac[2])

	vendors := map[string]string{
		"005056": "VMware",
		"000569": "VMware",
		"000C29": "VMware",
		"001C14": "VMware",
		"000D3A": "Microsoft",
		"000FFE": "Microsoft",
		"001DD8": "Microsoft",
		"0050F2": "Microsoft",
		"08002B": "DEC",
		"080009": "Hewlett Packard",
		"00000C": "Cisco",
		"00D0D3": "Olivetti",
		"020054": "Novell",
	}

	if vendor, ok := vendors[oui]; ok {
		return vendor
	}

	return ""
}

// buildNetBIOSSessionRequest builds a NetBIOS session request
func buildNetBIOSSessionRequest() []byte {
	request, _ := hex.DecodeString("81000044204543454e46444542454c454e454e46" +
		"414346414346414346414341434143414341000020" +
		"45444542454c454e454e46414346414346414341434143414341434143000")
	return request
}

// buildNetBIOSNameQuery builds a NetBIOS name query for node status
func buildNetBIOSNameQuery() []byte {
	// NetBIOS Node Status Request
	// Transaction ID: 0x80f0 (same as nmap for compatibility)
	// Flags: 0x0010 (Recursion Desired)
	// Questions: 1, Answers: 0, Authority: 0, Additional: 0
	// Name: * (encoded as CKAAA...)
	// Type: NBSTAT (0x0021), Class: IN (0x0001)
	query, _ := hex.DecodeString("80f00010000100000000000020434b4141414141" +
		"4141414141414141414141414141414141414141414141410000210001")
	return query
}
