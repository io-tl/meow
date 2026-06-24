package modules

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"time"

	"meow/grabber/pkg/enrichment/modules/helpers"
)

// MSSQLModule implements the Microsoft SQL Server enrichment module
type MSSQLModule struct {
	BaseModule
}

// MSSQLInstanceInfo represents a single SQL Server Browser instance entry.
type MSSQLInstanceInfo struct {
	ServerName   string            `json:"server_name,omitempty"`
	InstanceName string            `json:"instance_name,omitempty"`
	Version      string            `json:"version,omitempty"`
	TCPPort      string            `json:"tcp_port,omitempty"`
	NamedPipe    string            `json:"named_pipe,omitempty"`
	Clustered    string            `json:"clustered,omitempty"`
	Fields       map[string]string `json:"fields,omitempty"`
}

// MSSQLResult represents the enriched MSSQL data
type MSSQLResult struct {
	Protocol         string              `json:"protocol"`
	Version          string              `json:"version,omitempty"`
	VersionNumber    string              `json:"version_number,omitempty"`
	Product          string              `json:"product,omitempty"`
	ServerName       string              `json:"server_name,omitempty"`
	InstanceName     string              `json:"instance_name,omitempty"`
	Encryption       string              `json:"encryption,omitempty"`
	MARSSupported    bool                `json:"mars_supported,omitempty"`
	ThreadID         uint32              `json:"thread_id,omitempty"`
	TDSPacketType    string              `json:"tds_packet_type,omitempty"`
	BrowserReachable bool                `json:"browser_reachable,omitempty"`
	BrowserInstances []MSSQLInstanceInfo `json:"browser_instances,omitempty"`
	Error            string              `json:"error,omitempty"`
}

func init() {
	Register(&MSSQLModule{
		BaseModule: NewBaseModule(
			"mssql",
			[]string{"ms-sql", "ms-sql-s"},
			true,
			10*time.Second,
		),
	})
}

func (m *MSSQLModule) Scan(ip string, port int) (interface{}, error) {
	return scanMSSQL(ip, port, m.DefaultTimeout())
}

// scanMSSQL performs MSSQL enrichment.
func scanMSSQL(ip string, port int, timeout time.Duration) (*MSSQLResult, error) {
	result := &MSSQLResult{
		Protocol: "mssql",
	}

	conn, err := helpers.DialTCP(ip, port, timeout)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	defer conn.Close()

	prelogin := buildTDSPreloginPacket()
	if _, err := conn.Write(prelogin); err != nil {
		result.Error = err.Error()
		return result, err
	}

	header := make([]byte, 8)
	if _, err := io.ReadFull(conn, header); err != nil {
		result.Error = err.Error()
		return result, err
	}

	if header[0] != 0x04 {
		result.Error = "invalid TDS response"
		return result, nil
	}
	result.TDSPacketType = "TABULAR_RESULT"

	packetLength := int(binary.BigEndian.Uint16(header[2:4]))
	if packetLength < 8 || packetLength > 32768 {
		result.Error = fmt.Sprintf("invalid TDS packet length: %d", packetLength)
		return result, nil
	}

	payload := make([]byte, packetLength-8)
	if _, err := io.ReadFull(conn, payload); err != nil {
		result.Error = err.Error()
		return result, err
	}

	parseTDSPreloginResponse(result, payload)
	enrichWithBrowserInfo(result, ip, port, timeout)

	if result.Version == "" && result.VersionNumber != "" {
		result.Version = result.VersionNumber
	}
	if result.Error == "" && (result.Version != "" || result.InstanceName != "" || result.ServerName != "" || len(result.BrowserInstances) > 0) {
		return result, nil
	}
	if result.Error == "" {
		result.Error = "mssql detected but no detailed metadata returned"
	}

	return result, nil
}

// buildTDSPreloginPacket builds a TDS pre-login packet with the main metadata options enabled.
func buildTDSPreloginPacket() []byte {
	type option struct {
		token byte
		data  []byte
	}

	options := []option{
		{token: 0x00, data: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}}, // VERSION
		{token: 0x01, data: []byte{0x00}},                               // ENCRYPTION
		{token: 0x02, data: []byte("grabber\x00")},                      // INSTOPT
		{token: 0x03, data: []byte{0x00, 0x00, 0x00, 0x00}},             // THREADID
		{token: 0x04, data: []byte{0x01}},                               // MARS
	}

	tableLen := len(options)*5 + 1
	packet := make([]byte, 8, 8+tableLen+32)
	packet[0] = 0x12
	packet[1] = 0x01

	offset := tableLen
	for _, opt := range options {
		packet = append(packet, opt.token)
		packet = append(packet, byte(offset>>8), byte(offset))
		packet = append(packet, byte(len(opt.data)>>8), byte(len(opt.data)))
		offset += len(opt.data)
	}
	packet = append(packet, 0xff)
	for _, opt := range options {
		packet = append(packet, opt.data...)
	}

	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	return packet
}

func parseTDSPreloginResponse(result *MSSQLResult, payload []byte) {
	options, err := parseTDSPreloginOptions(payload)
	if err != nil {
		result.Error = err.Error()
		return
	}

	if version, ok := options[0x00]; ok && len(version) >= 6 {
		major := version[0]
		minor := version[1]
		build := binary.BigEndian.Uint16(version[2:4])
		subBuild := binary.BigEndian.Uint16(version[4:6])
		result.VersionNumber = fmt.Sprintf("%d.%02d.%d.%d", major, minor, build, subBuild)
		result.Product = mssqlProductName(major)
		result.Version = firstNonEmpty(mssqlProductLabel(major, result.VersionNumber), result.VersionNumber)
	}

	if enc, ok := options[0x01]; ok && len(enc) >= 1 {
		result.Encryption = mssqlEncryptionMode(enc[0])
	}

	if inst, ok := options[0x02]; ok {
		result.InstanceName = normalizeMSSQLInstanceName(inst)
	}

	if threadID, ok := options[0x03]; ok && len(threadID) >= 4 {
		result.ThreadID = binary.BigEndian.Uint32(threadID[:4])
	}

	if mars, ok := options[0x04]; ok && len(mars) >= 1 {
		result.MARSSupported = mars[0] != 0
	}
}

func parseTDSPreloginOptions(payload []byte) (map[byte][]byte, error) {
	options := make(map[byte][]byte)
	tableEnd := -1
	for i := 0; i < len(payload); {
		if payload[i] == 0xff {
			tableEnd = i + 1
			break
		}
		if i+5 > len(payload) {
			return nil, fmt.Errorf("truncated TDS prelogin option table")
		}
		_ = payload[i]
		_ = binary.BigEndian.Uint16(payload[i+1 : i+3])
		_ = binary.BigEndian.Uint16(payload[i+3 : i+5])
		i += 5
	}

	if tableEnd == -1 {
		return nil, fmt.Errorf("missing TDS prelogin terminator")
	}

	for i := 0; i+5 <= tableEnd-1; i += 5 {
		token := payload[i]
		offset := int(binary.BigEndian.Uint16(payload[i+1 : i+3]))
		length := int(binary.BigEndian.Uint16(payload[i+3 : i+5]))
		dataStart := offset
		if dataStart < tableEnd || dataStart+length > len(payload) {
			return nil, fmt.Errorf("invalid TDS prelogin option bounds")
		}
		options[token] = append([]byte(nil), payload[dataStart:dataStart+length]...)
	}

	return options, nil
}

func enrichWithBrowserInfo(result *MSSQLResult, ip string, port int, timeout time.Duration) {
	udpTimeout := timeout / 10
	if udpTimeout <= 0 {
		udpTimeout = 300 * time.Millisecond
	}
	if udpTimeout > 500*time.Millisecond {
		udpTimeout = 500 * time.Millisecond
	}

	conn, err := helpers.DialUDP(ip, 1434, udpTimeout)
	if err != nil {
		return
	}
	defer conn.Close()

	if _, err := conn.Write([]byte{0x03}); err != nil {
		return
	}

	data, err := helpers.ReadAvailable(conn, 8192)
	if err != nil || len(data) == 0 {
		return
	}

	instances := parseMSSQLBrowserResponse(data)
	if len(instances) == 0 {
		return
	}

	result.BrowserReachable = true
	result.BrowserInstances = instances

	for _, instance := range instances {
		if instance.TCPPort == fmt.Sprintf("%d", port) || (port == 1433 && instance.TCPPort == "") {
			result.ServerName = firstNonEmpty(result.ServerName, instance.ServerName)
			result.InstanceName = firstNonEmpty(result.InstanceName, instance.InstanceName)
			result.VersionNumber = firstNonEmpty(result.VersionNumber, instance.Version)
			if result.Version == "" && result.VersionNumber != "" {
				result.Version = firstNonEmpty(mssqlProductLabel(mssqlMajorVersion(result.VersionNumber), result.VersionNumber), result.VersionNumber)
			}
			break
		}
	}

	if result.ServerName == "" && len(instances) == 1 {
		result.ServerName = instances[0].ServerName
	}
	if result.InstanceName == "" && len(instances) == 1 {
		result.InstanceName = instances[0].InstanceName
	}
}

func parseMSSQLBrowserResponse(data []byte) []MSSQLInstanceInfo {
	data = bytesTrimBrowserPrefix(data)
	if len(data) == 0 {
		return nil
	}

	tokens := strings.Split(string(data), ";")
	var instances []MSSQLInstanceInfo
	current := MSSQLInstanceInfo{Fields: make(map[string]string)}

	flush := func() {
		if current.ServerName == "" && current.InstanceName == "" && len(current.Fields) == 0 {
			return
		}
		if len(current.Fields) == 0 {
			current.Fields = nil
		}
		instances = append(instances, current)
		current = MSSQLInstanceInfo{Fields: make(map[string]string)}
	}

	for i := 0; i < len(tokens); {
		key := strings.TrimSpace(tokens[i])
		if key == "" {
			i++
			continue
		}
		if i+1 >= len(tokens) {
			break
		}
		value := strings.TrimSpace(tokens[i+1])

		if key == "ServerName" && (current.ServerName != "" || current.InstanceName != "" || len(current.Fields) > 0) {
			flush()
		}

		current.Fields[key] = value
		switch strings.ToLower(key) {
		case "servername":
			current.ServerName = value
		case "instancename":
			current.InstanceName = value
		case "version":
			current.Version = value
		case "tcp":
			current.TCPPort = value
		case "np":
			current.NamedPipe = value
		case "isclustered":
			current.Clustered = value
		}
		i += 2
	}
	flush()

	return instances
}

func bytesTrimBrowserPrefix(data []byte) []byte {
	for len(data) > 0 && data[0] < 32 {
		data = data[1:]
	}
	return data
}

func normalizeMSSQLInstanceName(data []byte) string {
	name := strings.TrimSpace(helpers.ExtractNullTerminatedString(data))
	if name == "" {
		return ""
	}

	var cleaned strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
			cleaned.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			cleaned.WriteRune(r)
		case r >= '0' && r <= '9':
			cleaned.WriteRune(r)
		case r == '_' || r == '-' || r == '$' || r == '#':
			cleaned.WriteRune(r)
		}
	}

	name = cleaned.String()
	if len(name) < 2 {
		return ""
	}
	return name
}

func mssqlEncryptionMode(value byte) string {
	switch value {
	case 0x00:
		return "off"
	case 0x01:
		return "on"
	case 0x02:
		return "not_supported"
	case 0x03:
		return "required"
	case 0x04:
		return "strict"
	default:
		return fmt.Sprintf("unknown(0x%02x)", value)
	}
}

func mssqlMajorVersion(version string) byte {
	var major int
	fmt.Sscanf(version, "%d", &major)
	return byte(major)
}

func mssqlProductName(major byte) string {
	switch major {
	case 8:
		return "Microsoft SQL Server 2000"
	case 9:
		return "Microsoft SQL Server 2005"
	case 10:
		return "Microsoft SQL Server 2008/2008 R2"
	case 11:
		return "Microsoft SQL Server 2012"
	case 12:
		return "Microsoft SQL Server 2014"
	case 13:
		return "Microsoft SQL Server 2016"
	case 14:
		return "Microsoft SQL Server 2017"
	case 15:
		return "Microsoft SQL Server 2019"
	case 16:
		return "Microsoft SQL Server 2022"
	default:
		return ""
	}
}

func mssqlProductLabel(major byte, version string) string {
	name := mssqlProductName(major)
	if name == "" {
		return version
	}
	if version == "" {
		return name
	}
	return fmt.Sprintf("%s (%s)", name, version)
}
