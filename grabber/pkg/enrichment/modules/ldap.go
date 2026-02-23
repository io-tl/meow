package modules

import (
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"meow/grabber/pkg/enrichment/modules/helpers"
)

// LDAPResult represents the enriched LDAP data
type LDAPResult struct {
	Protocol                     string              `json:"protocol"` // ldap or ldaps
	RootDSE                      map[string][]string `json:"root_dse,omitempty"`
	SupportedLDAPVersion         []string            `json:"supported_ldap_version,omitempty"`
	NamingContexts               []string            `json:"naming_contexts,omitempty"`
	DefaultNamingContext         string              `json:"default_naming_context,omitempty"`
	ConfigurationNamingContext   string              `json:"configuration_naming_context,omitempty"`
	SchemaNamingContext          string              `json:"schema_naming_context,omitempty"`
	RootDomainNamingContext      string              `json:"root_domain_naming_context,omitempty"`
	DNSHostName                  string              `json:"dns_hostname,omitempty"`
	ServerName                   string              `json:"server_name,omitempty"`
	LDAPServiceName              string              `json:"ldap_service_name,omitempty"`
	DomainControllerFunctionality int                `json:"domain_controller_functionality,omitempty"`
	DomainFunctionality          int                 `json:"domain_functionality,omitempty"`
	ForestFunctionality          int                 `json:"forest_functionality,omitempty"`
	SupportedSASLMechanisms      []string            `json:"supported_sasl_mechanisms,omitempty"`
	SupportedControl             []string            `json:"supported_control,omitempty"`
	SupportedCapabilities        []string            `json:"supported_capabilities,omitempty"`
	CurrentTime                  string              `json:"current_time,omitempty"`
	SubschemaSubentry            string              `json:"subschema_subentry,omitempty"`
	IsGlobalCatalogReady         string              `json:"is_global_catalog_ready,omitempty"`
	IsSynchronized               string              `json:"is_synchronized,omitempty"`
	// Domain and Site extracted from naming contexts
	Domain                       string              `json:"domain,omitempty"`
	Site                         string              `json:"site,omitempty"`
	TLS                          *TLSInfo            `json:"tls,omitempty"` // For LDAPS
	Error                        string              `json:"error,omitempty"`
}

func init() {
	RegisterPlainAndTLS(
		"ldap", []string{},
		"ldaps", []string{},
		true, 10*time.Second,
		func(ip string, port int, useTLS bool, domain string, timeout time.Duration) (interface{}, error) {
			return scanLDAP(ip, port, useTLS, domain, timeout)
		},
	)
}

// scanLDAP performs LDAP/LDAPS enrichment
func scanLDAP(ip string, port int, useTLS bool, domain string, timeout time.Duration) (*LDAPResult, error) {
	protocol := "ldap"
	if useTLS {
		protocol = "ldaps"
	}

	result := &LDAPResult{
		Protocol: protocol,
		RootDSE:  make(map[string][]string),
	}

	var tlsConn *tls.Conn
	var conn interface {
		Read([]byte) (int, error)
		Write([]byte) (int, error)
		Close() error
	}
	var err error

	// Connect using helpers
	if useTLS {
		tlsConn, err = helpers.DialTLS(ip, port, domain, timeout)
		if err != nil {
			result.Error = err.Error()
			return result, err
		}
		defer tlsConn.Close()
		conn = tlsConn

		// Extract TLS info using helper and convert to shared TLSInfo
		result.TLS = TLSInfoFromHelpers(helpers.ExtractTLSInfo(tlsConn))
	} else {
		tcpConn, err := helpers.DialTCP(ip, port, timeout)
		if err != nil {
			result.Error = err.Error()
			return result, err
		}
		defer tcpConn.Close()
		conn = tcpConn
	}

	// Build LDAP search request for rootDSE with specific attributes
	searchRequest := buildLDAPSearchRequestWithAttributes()

	_, err = conn.Write(searchRequest)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	// Read response
	response := make([]byte, 8192)
	n, err := conn.Read(response)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	if n > 10 {
		// Parse BER-encoded response to extract rootDSE attributes
		parseLDAPResponse(response[:n], result)

		// Extract domain and site from naming contexts
		extractDomainAndSite(result)
	}

	// Send unbind request (SEQUENCE { messageID=2, UnbindRequest })
	unbindRequest, _ := hex.DecodeString("30050201024200")
	conn.Write(unbindRequest)

	return result, nil
}

// buildLDAPSearchRequest builds a simple LDAP search request for rootDSE
func buildLDAPSearchRequest() []byte {
	// Simplified LDAP search request (BER-encoded)
	// Search for rootDSE: base="", scope=base, filter=(objectClass=*)
	request, _ := hex.DecodeString("300c02010163070400000a010000")
	return request
}

// buildLDAPSearchRequestWithAttributes builds an LDAP search request with specific attributes
func buildLDAPSearchRequestWithAttributes() []byte {
	// Build search request for rootDSE with attributes
	// Message ID: 1
	messageID := []byte{0x02, 0x01, 0x01}

	// Search Request (application 3)
	// baseObject: "" (empty DN for rootDSE)
	baseObject := []byte{0x04, 0x00}

	// scope: baseObject (0)
	scope := []byte{0x0a, 0x01, 0x00}

	// derefAliases: neverDerefAliases (0)
	derefAliases := []byte{0x0a, 0x01, 0x00}

	// sizeLimit: 0 (no limit)
	sizeLimit := []byte{0x02, 0x01, 0x00}

	// timeLimit: 0 (no limit)
	timeLimit := []byte{0x02, 0x01, 0x00}

	// typesOnly: false
	typesOnly := []byte{0x01, 0x01, 0x00}

	// filter: (objectClass=*) - present filter
	filter := []byte{0x87, 0x0b, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x43, 0x6c, 0x61, 0x73, 0x73}

	// attributes: list of attributes to request
	attributes := buildAttributeList()

	// Combine all parts of search request
	searchContent := append(baseObject, scope...)
	searchContent = append(searchContent, derefAliases...)
	searchContent = append(searchContent, sizeLimit...)
	searchContent = append(searchContent, timeLimit...)
	searchContent = append(searchContent, typesOnly...)
	searchContent = append(searchContent, filter...)
	searchContent = append(searchContent, attributes...)

	// Add search request tag (application 3, constructed)
	searchRequest := []byte{0x63}
	searchRequest = append(searchRequest, encodeLDAPLength(len(searchContent))...)
	searchRequest = append(searchRequest, searchContent...)

	// Combine with message ID
	messageContent := append(messageID, searchRequest...)

	// Add message sequence tag
	message := []byte{0x30}
	message = append(message, encodeLDAPLength(len(messageContent))...)
	message = append(message, messageContent...)

	return message
}

// buildAttributeList builds the list of attributes to request
func buildAttributeList() []byte {
	attrs := []string{
		"namingContexts",
		"defaultNamingContext",
		"configurationNamingContext",
		"schemaNamingContext",
		"rootDomainNamingContext",
		"dnsHostName",
		"serverName",
		"ldapServiceName",
		"domainControllerFunctionality",
		"domainFunctionality",
		"forestFunctionality",
		"supportedLDAPVersion",
		"supportedSASLMechanisms",
		"supportedControl",
		"supportedCapabilities",
		"currentTime",
		"subschemaSubentry",
		"isGlobalCatalogReady",
		"isSynchronized",
		"dsServiceName",
	}

	var attrSequence []byte
	for _, attr := range attrs {
		// Each attribute is an OCTET STRING (0x04)
		attrBytes := []byte{0x04}
		attrBytes = append(attrBytes, byte(len(attr)))
		attrBytes = append(attrBytes, []byte(attr)...)
		attrSequence = append(attrSequence, attrBytes...)
	}

	// Wrap in SEQUENCE (0x30)
	result := []byte{0x30}
	result = append(result, encodeLDAPLength(len(attrSequence))...)
	result = append(result, attrSequence...)

	return result
}

// encodeLDAPLength encodes the length for BER encoding
func encodeLDAPLength(length int) []byte {
	if length < 128 {
		return []byte{byte(length)}
	}

	// Multi-byte length encoding
	var lengthBytes []byte
	temp := length
	for temp > 0 {
		lengthBytes = append([]byte{byte(temp & 0xff)}, lengthBytes...)
		temp >>= 8
	}

	// First byte indicates number of length bytes
	result := []byte{byte(0x80 | len(lengthBytes))}
	result = append(result, lengthBytes...)

	return result
}

// parseLDAPResponse parses the LDAP response and extracts attributes
func parseLDAPResponse(data []byte, result *LDAPResult) {
	// Simple BER parser for LDAP SearchResultEntry
	pos := 0

	// Skip message sequence tag and length
	if pos >= len(data) || data[pos] != 0x30 {
		return
	}
	pos++

	msgLen, bytesRead := decodeLDAPLength(data[pos:])
	if msgLen == 0 {
		return
	}
	pos += bytesRead

	// Skip message ID
	if pos >= len(data) || data[pos] != 0x02 {
		return
	}
	pos++
	idLen, bytesRead := decodeLDAPLength(data[pos:])
	pos += bytesRead + idLen

	// Look for SearchResultEntry (0x64)
	if pos >= len(data) || data[pos] != 0x64 {
		return
	}
	pos++

	entryLen, bytesRead := decodeLDAPLength(data[pos:])
	if entryLen == 0 {
		return
	}
	pos += bytesRead

	// Skip object name (DN) - should be empty for rootDSE
	if pos >= len(data) || data[pos] != 0x04 {
		return
	}
	pos++
	dnLen, bytesRead := decodeLDAPLength(data[pos:])
	pos += bytesRead + dnLen

	// Parse attributes sequence
	if pos >= len(data) || data[pos] != 0x30 {
		return
	}
	pos++

	attrsLen, bytesRead := decodeLDAPLength(data[pos:])
	pos += bytesRead

	endPos := pos + attrsLen

	// Parse each attribute
	for pos < endPos && pos < len(data) {
		// Each attribute is a SEQUENCE
		if data[pos] != 0x30 {
			break
		}
		pos++

		attrLen, bytesRead := decodeLDAPLength(data[pos:])
		pos += bytesRead
		attrEndPos := pos + attrLen

		// Get attribute name
		if pos >= len(data) || data[pos] != 0x04 {
			pos = attrEndPos
			continue
		}
		pos++

		nameLen, bytesRead := decodeLDAPLength(data[pos:])
		pos += bytesRead

		if pos+nameLen > len(data) {
			break
		}

		attrName := string(data[pos : pos+nameLen])
		pos += nameLen

		// Get attribute values (SET)
		if pos >= len(data) || data[pos] != 0x31 {
			pos = attrEndPos
			continue
		}
		pos++

		valuesLen, bytesRead := decodeLDAPLength(data[pos:])
		pos += bytesRead
		valuesEndPos := pos + valuesLen

		// Parse all values for this attribute
		var values []string
		for pos < valuesEndPos && pos < len(data) {
			if data[pos] != 0x04 {
				break
			}
			pos++

			valueLen, bytesRead := decodeLDAPLength(data[pos:])
			pos += bytesRead

			if pos+valueLen > len(data) {
				break
			}

			value := string(data[pos : pos+valueLen])
			values = append(values, value)
			pos += valueLen
		}

		// Store the attribute values in result
		storeAttribute(result, attrName, values)

		pos = attrEndPos
	}
}

// decodeLDAPLength decodes BER length encoding
func decodeLDAPLength(data []byte) (int, int) {
	if len(data) == 0 {
		return 0, 0
	}

	if data[0] < 128 {
		return int(data[0]), 1
	}

	// Multi-byte length
	numBytes := int(data[0] & 0x7f)
	if numBytes > len(data)-1 {
		return 0, 0
	}

	length := 0
	for i := 0; i < numBytes; i++ {
		length = (length << 8) | int(data[1+i])
	}

	return length, 1 + numBytes
}

// storeAttribute stores an attribute value in the result structure
func storeAttribute(result *LDAPResult, name string, values []string) {
	// Store in RootDSE map
	result.RootDSE[name] = values

	if len(values) == 0 {
		return
	}

	// Also store in specific fields for easy access
	switch strings.ToLower(name) {
	case "namingcontexts":
		result.NamingContexts = values
	case "defaultnamingcontext":
		result.DefaultNamingContext = values[0]
	case "configurationnamingcontext":
		result.ConfigurationNamingContext = values[0]
	case "schemanamingcontext":
		result.SchemaNamingContext = values[0]
	case "rootdomainnamingcontext":
		result.RootDomainNamingContext = values[0]
	case "dnshostname":
		result.DNSHostName = values[0]
	case "servername":
		result.ServerName = values[0]
	case "ldapservicename":
		result.LDAPServiceName = values[0]
	case "supportedldapversion":
		result.SupportedLDAPVersion = values
	case "supportedsaslmechanisms":
		result.SupportedSASLMechanisms = values
	case "supportedcontrol":
		result.SupportedControl = values
	case "supportedcapabilities":
		result.SupportedCapabilities = values
	case "currenttime":
		result.CurrentTime = values[0]
	case "subschemasubentry":
		result.SubschemaSubentry = values[0]
	case "isglobalcatalogready":
		result.IsGlobalCatalogReady = values[0]
	case "issynchronized":
		result.IsSynchronized = values[0]
	case "domaincontrollerfunctionality":
		// Try to parse as integer
		if len(values[0]) > 0 {
			var val int
			fmt.Sscanf(values[0], "%d", &val)
			result.DomainControllerFunctionality = val
		}
	case "domainfunctionality":
		if len(values[0]) > 0 {
			var val int
			fmt.Sscanf(values[0], "%d", &val)
			result.DomainFunctionality = val
		}
	case "forestfunctionality":
		if len(values[0]) > 0 {
			var val int
			fmt.Sscanf(values[0], "%d", &val)
			result.ForestFunctionality = val
		}
	}
}

// extractDomainAndSite extracts domain and site information from naming contexts
func extractDomainAndSite(result *LDAPResult) {
	// Extract domain from rootDomainNamingContext
	if result.RootDomainNamingContext != "" {
		domain := strings.ReplaceAll(result.RootDomainNamingContext, "DC=", "")
		domain = strings.ReplaceAll(domain, ",", ".")
		result.Domain = domain
	} else if result.DefaultNamingContext != "" {
		domain := strings.ReplaceAll(result.DefaultNamingContext, "DC=", "")
		domain = strings.ReplaceAll(domain, ",", ".")
		result.Domain = domain
	}

	// Extract site from serverName
	// Format: CN=SERVER,CN=Servers,CN=Site-Name,CN=Sites,...
	if result.ServerName != "" {
		parts := strings.Split(result.ServerName, ",")
		for i, part := range parts {
			if strings.HasPrefix(part, "CN=") && i > 0 {
				if strings.Contains(parts[i-1], "CN=Servers") {
					siteName := strings.TrimPrefix(part, "CN=")
					result.Site = siteName
					break
				}
			}
		}
		// Alternative pattern
		if result.Site == "" {
			for i, part := range parts {
				if strings.Contains(part, "CN=Sites") && i > 0 {
					siteName := strings.TrimPrefix(parts[i-1], "CN=")
					result.Site = siteName
					break
				}
			}
		}
	}
}
