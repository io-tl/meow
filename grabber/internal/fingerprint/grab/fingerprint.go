package grab

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Probe represents an nmap probe
type Probe struct {
	Protocol       string
	Name           string
	ProbeString    []byte
	Matches        []*Match
	Ports          []int
	SSLPorts       []int
	Rarity         int
	TotalWaitMS    int
	TCPWrappedMS   int
	Fallbacks      []string
	FallbackProbes []*Probe // Precompiled pointers to the fallback probes
}

// Match represents a matching rule
type Match struct {
	IsSoft      bool
	Pattern     *Regexp
	Service     string
	Product     string
	Version     string
	Info        string
	Hostname    string
	OS          string
	DeviceType  string
	CPE         []string
	VersionInfo map[string]string
}

// ServiceResult contains the result of the detection
type ServiceResult struct {
	Service           string
	Product           string
	Version           string
	Info              string
	Hostname          string
	OS                string
	DeviceType        string
	CPE               []string
	Probe             string
	isSoft            bool
	Uncertain         bool // Service guessed from nmap-services without a probe match
	RawResponse       string
	NullProbeResponse string             // Raw response from the NULL probe (for analysis)
	TLSVersion        uint16             // TLS version (ex: 0x0303 = TLS 1.2)
	CipherSuite       uint16             // Cipher suite negotiated
	ServerName        string             // SNI server name
	Certificates      []*tls.Certificate // Raw certificates chain (DEPRECATED - use CertificatesPEM)
	CertificatesPEM   []string           // PEM-encoded certificates
	JARMFingerprint   string             // JARM TLS fingerprint
}

/**
// String formats the result like nmap
func (r *ServiceResult) String() string {
	var parts []string

	if r.Product != "" {
		parts = append(parts, r.Product)
	}
	if r.Version != "" {
		parts = append(parts, r.Version)
	}

	result := strings.Join(parts, " ")

	// Add the info in parentheses if present
	if r.Info != "" {
		if result != "" {
			result += " (" + r.Info + ")"
		} else {
			result = r.Info
		}
	}

	return result
}

// FullString returns the full format including the service
func (r *ServiceResult) FullString() string {
	version := r.String()
	if version != "" {
		return r.Service + " " + version
	}
	return r.Service
}
**/
// ProbeDB contains all the probes
type ProbeDB struct {
	Probes       []*Probe
	NullProbe    *Probe
	ExcludePorts map[int]bool
	PortServices map[int]string // port->service mapping from nmap-services
	Debug        bool           // Debug mode to display the tested probes
}

// LoadProbes loads the nmap-service-probes file from an io.Reader
func LoadProbes(reader io.Reader) (*ProbeDB, error) {
	db := &ProbeDB{
		ExcludePorts: make(map[int]bool),
		PortServices: make(map[int]string),
	}

	scanner := bufio.NewScanner(reader)
	var currentProbe *Probe

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "Exclude ") {
			parseExclude(db, line[8:])
		} else if strings.HasPrefix(line, "Probe ") {
			if currentProbe != nil {
				db.Probes = append(db.Probes, currentProbe)
				if currentProbe.Name == "NULL" {
					db.NullProbe = currentProbe
				}
			}
			currentProbe = parseProbe(line)
		} else if currentProbe != nil {
			if strings.HasPrefix(line, "match ") {
				if m := parseMatch(line[6:], false); m != nil {
					currentProbe.Matches = append(currentProbe.Matches, m)
				}
			} else if strings.HasPrefix(line, "softmatch ") {
				if m := parseMatch(line[10:], true); m != nil {
					currentProbe.Matches = append(currentProbe.Matches, m)
				}
			} else if strings.HasPrefix(line, "ports ") {
				currentProbe.Ports = parsePorts(line[6:])
			} else if strings.HasPrefix(line, "sslports ") {
				currentProbe.SSLPorts = parsePorts(line[9:])
			} else if strings.HasPrefix(line, "rarity ") {
				if r, err := strconv.Atoi(strings.TrimSpace(line[7:])); err == nil {
					currentProbe.Rarity = r
				}
			} else if strings.HasPrefix(line, "totalwaitms ") {
				if t, err := strconv.Atoi(strings.TrimSpace(line[12:])); err == nil {
					// Validation like nmap: between 100 and 300000 ms
					if t < 100 || t > 300000 {
						log.Printf("Warning: totalwaitms must be between 100 and 300000, got %d (using default)\n", t)
						currentProbe.TotalWaitMS = 5000
					} else {
						currentProbe.TotalWaitMS = t
					}
				}
			} else if strings.HasPrefix(line, "tcpwrappedms ") {
				if t, err := strconv.Atoi(strings.TrimSpace(line[13:])); err == nil {
					// Validation like nmap: between 100 and 300000 ms
					if t < 100 || t > 300000 {
						log.Printf("Warning: tcpwrappedms must be between 100 and 300000, got %d (using default)\n", t)
						currentProbe.TCPWrappedMS = 2000
					} else {
						currentProbe.TCPWrappedMS = t
					}
				}
			} else if strings.HasPrefix(line, "fallback ") {
				fb := strings.TrimSpace(line[9:])
				currentProbe.Fallbacks = strings.Split(fb, ",")
				for i := range currentProbe.Fallbacks {
					currentProbe.Fallbacks[i] = strings.TrimSpace(currentProbe.Fallbacks[i])
				}
			}
		}
	}

	if currentProbe != nil {
		db.Probes = append(db.Probes, currentProbe)
		if currentProbe.Name == "NULL" {
			db.NullProbe = currentProbe
		}
	}

	// Compile the fallbacks (like nmap)
	db.compileFallbacks()

	return db, scanner.Err()
}

// LoadServices loads the nmap-services file from an io.Reader for the port->service mapping
func (db *ProbeDB) LoadServices(reader io.Reader) error {
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Ignore empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Format: service_name port/protocol frequency [comment]
		// Example: irc	6667/tcp	0.000652	# Internet Relay Chat
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		serviceName := fields[0]
		portProto := fields[1]

		// Parse port/protocol
		parts := strings.Split(portProto, "/")
		if len(parts) != 2 {
			continue
		}

		port, err := strconv.Atoi(parts[0])
		if err != nil {
			continue
		}

		protocol := parts[1]

		// Only keep TCP for now
		if protocol == "tcp" {
			// If the port does not already have a service, add it
			if _, exists := db.PortServices[port]; !exists {
				db.PortServices[port] = serviceName
			}
		}
	}

	return scanner.Err()
}

// compileFallbacks precompiles the fallbacks into pointers (like nmap)
func (db *ProbeDB) compileFallbacks() {
	// Special case: NULL probe
	if db.NullProbe != nil {
		db.NullProbe.FallbackProbes = append(db.NullProbe.FallbackProbes, db.NullProbe)
	}

	for _, probe := range db.Probes {
		// Always start with the probe itself
		probe.FallbackProbes = append(probe.FallbackProbes, probe)

		// Add the fallbacks specified in the directive
		for _, fbName := range probe.Fallbacks {
			fbProbe := db.getProbeByName(fbName)
			if fbProbe != nil {
				probe.FallbackProbes = append(probe.FallbackProbes, fbProbe)
			}
		}

		// For TCP: add the NULL probe at the end (automatic)
		if probe.Protocol == "TCP" && db.NullProbe != nil {
			// Avoid duplicating if the probe is itself NULL
			if probe.Name != "NULL" {
				probe.FallbackProbes = append(probe.FallbackProbes, db.NullProbe)
			}
		}
	}
}

// getProbeByName finds a probe by its name
func (db *ProbeDB) getProbeByName(name string) *Probe {
	if db.NullProbe != nil && db.NullProbe.Name == name {
		return db.NullProbe
	}
	for _, probe := range db.Probes {
		if probe.Name == name {
			return probe
		}
	}
	return nil
}

func parseExclude(db *ProbeDB, s string) {
	parts := strings.Split(s, ":")
	if len(parts) < 2 {
		return
	}
	ports := parsePorts(parts[1])
	for _, p := range ports {
		db.ExcludePorts[p] = true
	}
}

func parseProbe(line string) *Probe {
	parts := strings.Fields(line[6:])
	if len(parts) < 3 {
		return nil
	}

	p := &Probe{
		Protocol:     parts[0],
		Name:         parts[1],
		Rarity:       5,
		TotalWaitMS:  5000,
		TCPWrappedMS: 2000,
	}

	p.ProbeString = []byte(unescapeProbeString(strings.Join(parts[2:], " ")))
	return p
}

func parseMatch(s string, isSoft bool) *Match {
	parts := strings.SplitN(s, " ", 2)
	if len(parts) < 2 {
		return nil
	}

	service := parts[0]
	pattern, flags, versionInfo := parsePattern(parts[1])

	if pattern == "" {
		return nil
	}

	// Strict flag validation (like nmap: only 'i' and 's')
	for _, flag := range flags {
		if flag != 'i' && flag != 's' {
			// Nmap rejects the other flags (notably 'm')
			return nil
		}
	}

	// Build the PCRE options by combining the flags
	opts := CompileOption(0)
	if strings.Contains(flags, "i") {
		opts |= Caseless
	}
	if strings.Contains(flags, "s") {
		opts |= DotAll
	}

	var re *Regexp
	var err error
	if opts != 0 {
		re, err = CompilePatternOpts(pattern, opts)
	} else {
		re, err = CompilePattern(pattern)
	}
	if err != nil {
		return nil
	}

	m := &Match{
		IsSoft:      isSoft,
		Pattern:     re,
		Service:     service,
		VersionInfo: make(map[string]string),
	}

	parseVersionInfo(versionInfo, m)
	return m
}

func parsePattern(s string) (pattern, flags, versionInfo string) {
	if len(s) < 3 || s[0] != 'm' {
		return
	}

	delim := s[1]
	escaped := false
	i := 2

	for i < len(s) {
		if escaped {
			escaped = false
		} else if s[i] == '\\' {
			escaped = true
		} else if s[i] == byte(delim) {
			pattern = s[2:i]
			i++
			break
		}
		i++
	}

	for i < len(s) && (s[i] == 'i' || s[i] == 's' || s[i] == 'm') {
		flags += string(s[i])
		i++
	}

	if i < len(s) {
		versionInfo = strings.TrimSpace(s[i:])
	}

	// Do NOT unescape the patterns - they are already in correct regex format
	return
}

func parseVersionInfo(info string, m *Match) {
	parts := splitVersionInfo(info)

	for _, part := range parts {
		if len(part) < 3 {
			continue
		}

		key := part[:2]
		val := part[2:]

		// Remove the trailing '/' if present
		if len(val) > 0 && val[len(val)-1] == '/' {
			val = val[:len(val)-1]
		}

		switch key {
		case "p/":
			m.Product = val
		case "v/":
			m.Version = val
		case "i/":
			m.Info = val
		case "h/":
			m.Hostname = val
		case "o/":
			m.OS = val
		case "d/":
			m.DeviceType = val
		case "cp":
			if strings.HasPrefix(part, "cpe:/") {
				m.CPE = append(m.CPE, part[5:])
			}
		}
	}
}

func splitVersionInfo(info string) []string {
	var parts []string
	var current strings.Builder
	escaped := false

	for i := 0; i < len(info); i++ {
		if escaped {
			current.WriteByte(info[i])
			escaped = false
		} else if info[i] == '\\' {
			escaped = true
			current.WriteByte(info[i])
		} else if info[i] == '/' && i+3 < len(info) && info[i+1] == ' ' {
			// Finish the current part with the '/'
			current.WriteByte(info[i])
			if s := current.String(); s != "" {
				parts = append(parts, s)
			}
			current.Reset()
			// Skip the space
			i++
		} else {
			current.WriteByte(info[i])
		}
	}

	if s := current.String(); s != "" {
		parts = append(parts, s)
	}

	return parts
}

func unescapeProbeString(s string) string {
	if len(s) < 2 || s[0] != 'q' {
		return s
	}

	if len(s) < 3 {
		return ""
	}

	delim := s[1]
	end := strings.LastIndexByte(s, delim)
	if end <= 2 {
		return s
	}

	return unescapePattern(s[2:end])
}

func unescapePattern(s string) string {
	var result strings.Builder
	i := 0

	for i < len(s) {
		if s[i] == '\\' && i+1 < len(s) {
			i++
			switch s[i] {
			case '0':
				result.WriteByte(0)
			case 'a': // Bell (BEL)
				result.WriteByte('\a')
			case 'b': // Backspace (BS)
				result.WriteByte('\b')
			case 'f': // Form feed (FF)
				result.WriteByte('\f')
			case 'n': // Line feed (LF)
				result.WriteByte('\n')
			case 'r': // Carriage return (CR)
				result.WriteByte('\r')
			case 't': // Horizontal tab (TAB)
				result.WriteByte('\t')
			case 'v': // Vertical tab (VT)
				result.WriteByte('\v')
			case 'x':
				if i+2 < len(s) {
					hex := s[i+1 : i+3]
					if val, err := strconv.ParseInt(hex, 16, 32); err == nil {
						result.WriteByte(byte(val))
						i += 2
					} else {
						result.WriteByte('\\')
						result.WriteByte('x')
					}
				} else {
					result.WriteByte('\\')
					result.WriteByte('x')
				}
			case '\\':
				result.WriteByte('\\')
			default:
				// Nmap rejects octal sequences (numbers)
				if (s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'z') || (s[i] >= 'A' && s[i] <= 'Z') {
					// Alphanumeric character after '\': invalid (like nmap)
					// We return the string as-is in case of error
					return s
				}
				// Other characters: copy as-is (for \", \|, etc.)
				result.WriteByte(s[i])
			}
		} else {
			result.WriteByte(s[i])
		}
		i++
	}

	return result.String()
}

func parsePorts(s string) []int {
	var ports []int
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if strings.Contains(p, "-") {
			parts := strings.Split(p, "-")
			if len(parts) == 2 {
				start, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
				end, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
				if err1 == nil && err2 == nil {
					for i := start; i <= end; i++ {
						ports = append(ports, i)
					}
				}
			}
		} else if port, err := strconv.Atoi(p); err == nil {
			ports = append(ports, port)
		}
	}
	return ports
}

// buildProbeQueue builds the probe queue following the nmap algorithm.
// Follows nmap's 3 strict states (service_scan.cc nextProbe()):
//  1. PROBESTATE_NULLPROBE: NULL probe (TCP only)
//  2. PROBESTATE_MATCHINGPROBES: probes whose ports/sslports contain this port
//  3. PROBESTATE_NONMATCHINGPROBES: remaining probes filtered by rarity <= intensity
func (db *ProbeDB) buildProbeQueue(port int, ssl bool, intensity int) []*Probe {
	var queue []*Probe
	seen := make(map[string]bool)

	// State 1: NULL probe for TCP (captures unsolicited banners)
	if db.NullProbe != nil && db.NullProbe.Protocol == "TCP" {
		queue = append(queue, db.NullProbe)
		seen[db.NullProbe.Name] = true
	}

	// State 2: Matching probes - probes whose ports/sslports list contains this port
	if ssl {
		// SSL mode: sslports-matching first, then ports-matching
		for _, probe := range db.Probes {
			if probe.Protocol != "TCP" || seen[probe.Name] {
				continue
			}
			if containsPort(probe.SSLPorts, port) {
				queue = append(queue, probe)
				seen[probe.Name] = true
			}
		}
		for _, probe := range db.Probes {
			if probe.Protocol != "TCP" || seen[probe.Name] {
				continue
			}
			if containsPort(probe.Ports, port) {
				queue = append(queue, probe)
				seen[probe.Name] = true
			}
		}
	} else {
		// Non-SSL mode: ports-matching first, then sslports-matching
		for _, probe := range db.Probes {
			if probe.Protocol != "TCP" || seen[probe.Name] {
				continue
			}
			if containsPort(probe.Ports, port) {
				queue = append(queue, probe)
				seen[probe.Name] = true
			}
		}
		for _, probe := range db.Probes {
			if probe.Protocol != "TCP" || seen[probe.Name] {
				continue
			}
			if containsPort(probe.SSLPorts, port) {
				queue = append(queue, probe)
				seen[probe.Name] = true
			}
		}
	}

	// State 3: Non-matching probes filtered by rarity <= intensity
	// (like nmap's PROBESTATE_NONMATCHINGPROBES)
	for _, probe := range db.Probes {
		if probe.Protocol != "TCP" || seen[probe.Name] {
			continue
		}
		if probe.Rarity <= intensity {
			queue = append(queue, probe)
			seen[probe.Name] = true
		}
	}

	return queue
}

// serviceIsPossible checks if a probe has any match pattern for the given service.
// This mirrors nmap's ServiceProbe::serviceIsPossible() which is used to filter
// probes after a softmatch: only probes that could potentially match the detected
// service are tested, dramatically reducing unnecessary probe attempts.
func (p *Probe) serviceIsPossible(service string) bool {
	for _, m := range p.Matches {
		if strings.EqualFold(m.Service, service) {
			return true
		}
	}
	return false
}

func containsPort(ports []int, port int) bool {
	for _, p := range ports {
		if p == port {
			return true
		}
	}
	return false
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func extractHTTPHeaders(data []byte) string {
	// Find the end of the HTTP headers (double CRLF)
	dataStr := string(data)

	// HTTP uses \r\n\r\n to separate headers and body
	if idx := strings.Index(dataStr, "\r\n\r\n"); idx != -1 {
		return dataStr[:idx+4] // Include the double CRLF
	}
	// Fallback for \n\n
	if idx := strings.Index(dataStr, "\n\n"); idx != -1 {
		return dataStr[:idx+2]
	}

	// If no separator found, return everything (probably just the headers)
	return dataStr
}

func readResponse(conn net.Conn, timeout time.Duration) []byte {
	var response []byte
	buf := make([]byte, 4096)
	maxBytes := 65536

	conn.SetReadDeadline(time.Now().Add(timeout))

	for len(response) < maxBytes {
		n, err := conn.Read(buf)
		if n > 0 {
			response = append(response, buf[:n]...)
			// After the first read, use a short timeout for additional data
			conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		}
		if err != nil {
			break
		}
	}

	return response
}

// safeRegexMatch executes a regex match with a timeout to avoid ReDoS attacks
func safeRegexMatch(pattern *Regexp, data string, timeout time.Duration) (bool, []string) {
	type matchResult struct {
		matched bool
		groups  []string
	}

	resultChan := make(chan matchResult, 1)

	go func() {
		matched := pattern.MatchString(data)
		var groups []string
		if matched {
			groups = pattern.FindStringSubmatch(data)
		}
		resultChan <- matchResult{matched: matched, groups: groups}
	}()

	select {
	case result := <-resultChan:
		return result.matched, result.groups
	case <-time.After(timeout):
		// Timeout: possible ReDoS attack
		return false, nil
	}
}

func (db *ProbeDB) testMatches(probe *Probe, response []byte, filterService string) *ServiceResult {
	// Limit the response size to avoid overly long regexes
	maxMatchSize := 16384
	matchResponse := response
	if len(response) > maxMatchSize {
		matchResponse = response[:maxMatchSize]
	}
	responseStr := string(matchResponse)

	// nmap behavior: return the FIRST match found (first-match-wins)
	// instead of collecting all matches and choosing the best score
	for _, match := range probe.Matches {
		// If filtering by service, check compatibility
		if filterService != "" && !match.serviceMatches(filterService) {
			continue
		}

		// Use safeRegexMatch with a 5 second timeout (ReDoS protection)
		matched, groups := safeRegexMatch(match.Pattern, responseStr, 5*time.Second)
		if !matched {
			continue
		}

		// If no captured groups, use the full match
		if groups == nil {
			groups = []string{responseStr}
		}

		result := &ServiceResult{
			Service:    match.Service,
			Product:    expandRefs(match.Product, groups),
			Version:    expandRefs(match.Version, groups),
			Info:       expandRefs(match.Info, groups),
			Hostname:   expandRefs(match.Hostname, groups),
			OS:         expandRefs(match.OS, groups),
			DeviceType: expandRefs(match.DeviceType, groups),
			CPE:        match.CPE,
			isSoft:     match.IsSoft,
		}

		// Debug: display the match details
		if db.Debug {
			log.Printf("[DEBUG-MATCH] service=%s soft=%v product_tpl=%q product=%q version=%q",
				result.Service, result.isSoft, match.Product, result.Product, result.Version)
		}

		// Fix: force soft match for HTTP without Product (nmap behavior)
		// An HTTP match without Product is considered generic/soft
		if !result.isSoft && result.Product == "" {
			if result.Service == "http" || result.Service == "https" || result.Service == "ssl/http" {
				result.isSoft = true
			}
		}

		// FIRST-MATCH-WINS: return the first match found immediately
		return result
	}

	// No match found
	return nil
}

func (db *ProbeDB) testFallbacks(probe *Probe, response []byte) *ServiceResult {
	// Use the precompiled fallbacks (faster than searching by name)
	for _, fbProbe := range probe.FallbackProbes {
		// Ignore the probe itself (already tested)
		if fbProbe == probe {
			continue
		}

		if result := db.testMatches(fbProbe, response, ""); result != nil {
			return result
		}
	}

	return nil
}

func (m *Match) serviceMatches(service string) bool {
	return strings.EqualFold(m.Service, service)
}

func (r *ServiceResult) IsSoft() bool {
	// A result is considered soft if it has little info
	return r.Product == "" && r.Version == ""
}

func expandRefs(s string, groups []string) string {
	if s == "" {
		return s
	}

	var result strings.Builder
	i := 0

	for i < len(s) {
		if s[i] == '$' && i+1 < len(s) {
			// Find the end of the variable
			varStart := i
			i++

			// Simple $N (a single digit)
			if s[i] >= '1' && s[i] <= '9' {
				num := int(s[i] - '0')
				if num < len(groups) {
					result.WriteString(groups[num])
				}
				i++
				continue
			}

			// Advanced commands: $P(), $SUBST(), $I()
			if s[i] >= 'A' && s[i] <= 'Z' {
				cmdStart := i
				// Find the end of the command name
				for i < len(s) && s[i] >= 'A' && s[i] <= 'Z' {
					i++
				}
				cmdName := s[cmdStart:i]

				// Must be followed by '('
				if i >= len(s) || s[i] != '(' {
					// Not a valid command, copy as-is
					result.WriteString(s[varStart:i])
					continue
				}

				// Find the closing parenthesis
				parenStart := i
				depth := 1
				i++
				for i < len(s) && depth > 0 {
					if s[i] == '(' {
						depth++
					} else if s[i] == ')' {
						depth--
					} else if s[i] == '\\' && i+1 < len(s) {
						i++ // Skip escaped char
					}
					i++
				}

				if depth != 0 {
					// Unclosed parentheses
					result.WriteString(s[varStart:])
					break
				}

				// Extract the arguments
				argsStr := s[parenStart+1 : i-1]
				expansion := processSubstCommand(cmdName, argsStr, groups)
				result.WriteString(expansion)
				continue
			}

			// Invalid character after $
			result.WriteByte('$')
		} else {
			result.WriteByte(s[i])
			i++
		}
	}

	return result.String()
}

// processSubstCommand handles the advanced substitution commands
func processSubstCommand(cmd string, argsStr string, groups []string) string {
	switch cmd {
	case "P":
		// $P(N) - filters printable characters
		return substP(argsStr, groups)
	case "SUBST":
		// $SUBST(N,"find","replace")
		return substSUBST(argsStr, groups)
	case "I":
		// $I(N,"<"|">")
		return substI(argsStr, groups)
	default:
		return ""
	}
}

// substP filters the printable characters
func substP(argsStr string, groups []string) string {
	num, err := strconv.Atoi(strings.TrimSpace(argsStr))
	if err != nil || num < 1 || num > 9 || num >= len(groups) {
		return ""
	}

	var result strings.Builder
	for _, ch := range groups[num] {
		if ch >= 32 && ch < 127 {
			result.WriteRune(ch)
		}
	}
	return result.String()
}

// substSUBST performs a string replacement
func substSUBST(argsStr string, groups []string) string {
	// Parse: N,"find","replace"
	args := parseSubstArgs(argsStr)
	if len(args) != 3 {
		return ""
	}

	num, err := strconv.Atoi(args[0])
	if err != nil || num < 1 || num > 9 || num >= len(groups) {
		return ""
	}

	find := args[1]
	replace := args[2]

	return strings.ReplaceAll(groups[num], find, replace)
}

// substI converts binary bytes to an integer
func substI(argsStr string, groups []string) string {
	// Parse: N,"<"|">"
	args := parseSubstArgs(argsStr)
	if len(args) != 2 {
		return ""
	}

	num, err := strconv.Atoi(args[0])
	if err != nil || num < 1 || num > 9 || num >= len(groups) {
		return ""
	}

	endian := args[1]
	if endian != "<" && endian != ">" {
		return ""
	}

	data := []byte(groups[num])
	if len(data) > 8 {
		// Overflow protection
		return ""
	}

	var val uint64
	if endian == ">" {
		// Big-endian
		for _, b := range data {
			val = (val << 8) | uint64(b)
		}
	} else {
		// Little-endian
		for i := len(data) - 1; i >= 0; i-- {
			val = (val << 8) | uint64(data[i])
		}
	}

	return strconv.FormatUint(val, 10)
}

// parseSubstArgs parses the comma-separated arguments, handling quoted strings
func parseSubstArgs(s string) []string {
	var args []string
	var current strings.Builder
	inQuotes := false
	escaped := false

	for i := 0; i < len(s); i++ {
		ch := s[i]

		if escaped {
			current.WriteByte(ch)
			escaped = false
			continue
		}

		if ch == '\\' {
			escaped = true
			continue
		}

		if ch == '"' {
			inQuotes = !inQuotes
			continue
		}

		if ch == ',' && !inQuotes {
			// Add even if empty (to support empty strings like "")
			args = append(args, strings.TrimSpace(current.String()))
			current.Reset()
			continue
		}

		current.WriteByte(ch)
	}

	// Always add the last argument, even if it is empty
	args = append(args, strings.TrimSpace(current.String()))

	return args
}

// ScanPortAuto scans a port with SSL detection based on the port number
func (db *ProbeDB) ScanPortAuto(host string, port int, timeout time.Duration, intensity int) (*ServiceResult, error) {
	// Standard SSL ports: try directly in SSL
	sslPorts := map[int]bool{
		443: true, 8443: true, 9443: true, 4443: true, // HTTPS
		465: true, 587: true, 993: true, 995: true, // Email SSL
		636: true, 3269: true, // LDAPS
		989: true, 990: true, // FTPS
		5986: true, 8531: true, // WinRM HTTPS
	}

	// If it is a standard SSL port, try directly in SSL
	if sslPorts[port] {
		result, err := db.GrabPort(host, port, timeout, true, intensity)
		// If successful, return
		if err == nil && result != nil {
			return result, nil
		}
		// If it fails on a standard SSL port, fall back to non-SSL
		return db.GrabPort(host, port, timeout, false, intensity)
	}

	// For the other ports: try first without SSL
	result, err := db.GrabPort(host, port, timeout, false, intensity)

	// If the detected service starts with "ssl/", it means the service requires SSL
	// (nmap-service-probes convention: ssl/http, ssl/imap, etc.)
	// In that case, automatically retry in SSL
	if result != nil && strings.HasPrefix(result.Service, "ssl/") {
		resultSSL, errSSL := db.GrabPort(host, port, timeout, true, intensity)
		if errSSL == nil && resultSSL != nil {
			return resultSSL, nil
		}
		// If SSL fails, still convert ssl/* into the appropriate SSL service
		// to ensure consistency in the database
		switch result.Service {
		case "ssl/http":
			result.Service = "https"
		case "ssl/imap":
			result.Service = "imaps"
		case "ssl/pop3":
			result.Service = "pop3s"
		case "ssl/smtp":
			result.Service = "smtps"
		}
		return result, nil
	}

	// If successful with a hard result and product, return
	if result != nil && !result.isSoft && result.Product != "" {
		return result, nil
	}

	// If soft match HTTP on a standard HTTP port, do not retry SSL (nmap optimization)
	if result != nil && result.isSoft &&
		(result.Service == "http" || result.Service == "https") &&
		(port == 80 || port == 8080 || port == 8000 || port == 8888) {
		return result, nil
	}

	// If no result or soft result, retry in SSL
	// This allows detecting SSL services on non-standard ports
	resultSSL, errSSL := db.GrabPort(host, port, timeout, true, intensity)
	if errSSL == nil && resultSSL != nil {
		return resultSSL, nil
	}

	// If the SSL scan failed but the non-SSL scan succeeded, return the non-SSL result
	if result != nil {
		return result, err
	}

	// Otherwise return the SSL result
	return resultSSL, errSSL
}

// isPortClosedError quickly detects whether a port is closed/unreachable
func isPortClosedError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "no route to host") ||
		strings.Contains(errStr, "connection reset") ||
		strings.Contains(errStr, "network is unreachable")
}

// TLSConnectionInfo contains the TLS connection information
type TLSConnectionInfo struct {
	Conn            net.Conn
	TLSVersion      uint16
	CipherSuite     uint16
	ServerName      string
	CertificatesPEM []string
}

// connectToPort opens a TCP or TLS connection
// Returns (conn, tlsInfo, error)
func connectToPort(host string, port int, timeout time.Duration, useSSL bool) (net.Conn, *TLSConnectionInfo, error) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	if useSSL {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         host,
		}
		dialer := &net.Dialer{Timeout: timeout}
		tlsConn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
		if err != nil {
			return nil, nil, fmt.Errorf("TLS connection failed: %w", err)
		}

		// Extract the TLS information
		state := tlsConn.ConnectionState()
		tlsInfo := &TLSConnectionInfo{
			Conn:            tlsConn,
			TLSVersion:      state.Version,
			CipherSuite:     state.CipherSuite,
			ServerName:      state.ServerName,
			CertificatesPEM: make([]string, 0, len(state.PeerCertificates)),
		}

		// Convert the certificates to PEM
		for _, cert := range state.PeerCertificates {
			pem := EncodeCertToPEM(cert.Raw)
			tlsInfo.CertificatesPEM = append(tlsInfo.CertificatesPEM, pem)
		}

		return tlsConn, tlsInfo, nil
	}

	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, nil, fmt.Errorf("TCP connection failed: %w", err)
	}
	return conn, nil, nil
}

// EncodeCertToPEM encodes a DER certificate to PEM
func EncodeCertToPEM(derBytes []byte) string {
	// Standard PEM format
	encoded := "-----BEGIN CERTIFICATE-----\n"
	// Base64 encode with wrapping at 64 characters
	b64 := Base64Encode(derBytes)
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

// Base64Encode encodes to standard base64
func Base64Encode(data []byte) string {
	const base64Table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var result strings.Builder
	n := len(data)

	for i := 0; i < n; i += 3 {
		// Read up to 3 bytes
		b1 := data[i]
		var b2, b3 byte
		if i+1 < n {
			b2 = data[i+1]
		}
		if i+2 < n {
			b3 = data[i+2]
		}

		// Convert to 4 base64 characters
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

// attachTLSInfo attaches the TLS information to a result and computes JARM if TLS is detected
func attachTLSInfo(result *ServiceResult, tlsInfo *TLSConnectionInfo, host string, port int) {
	if result == nil {
		return
	}

	// If we already have TLS info, use it
	if tlsInfo != nil {
		result.TLSVersion = tlsInfo.TLSVersion
		result.CipherSuite = tlsInfo.CipherSuite
		result.ServerName = tlsInfo.ServerName
		result.CertificatesPEM = tlsInfo.CertificatesPEM

		if len(tlsInfo.CertificatesPEM) > 0 && host != "" && port > 0 {
			jarm := calculateJARMHash(host, uint(port))
			if jarm != "" {
				result.JARMFingerprint = jarm
			}
		}
		return
	}

	// If we have no TLS info but an SSL service was detected
	// (via a raw probe like SSLSessionReq), make a real TLS connection
	// to extract the certificates and compute JARM
	if isSSLService(result.Service) && host != "" && port > 0 {
		conn, extractedTLSInfo, err := connectToPort(host, port, 5*time.Second, true)
		if err == nil && extractedTLSInfo != nil {
			conn.Close()
			result.TLSVersion = extractedTLSInfo.TLSVersion
			result.CipherSuite = extractedTLSInfo.CipherSuite
			result.ServerName = extractedTLSInfo.ServerName
			result.CertificatesPEM = extractedTLSInfo.CertificatesPEM

			if len(extractedTLSInfo.CertificatesPEM) > 0 {
				jarm := calculateJARMHash(host, uint(port))
				if jarm != "" {
					result.JARMFingerprint = jarm
				}
			}
		}
	}
}

// isSSLService detects whether a service uses SSL/TLS
func isSSLService(service string) bool {
	// Common SSL/TLS services
	sslServices := []string{
		"ssl", "https", "imaps", "pop3s", "smtps", "ftps", "ldaps", "nrpe",
		"ssl/http", "ssl/imap", "ssl/pop3", "ssl/smtp", "ssl/ftp",
		"smb-ssl", "mysql-ssl", "postgresql-ssl", "rdp-ssl",
	}
	for _, s := range sslServices {
		if service == s {
			return true
		}
	}
	return false
}

// ProbeServiceMultiConn tests several probes by opening one connection per probe
func (db *ProbeDB) ProbeServiceMultiConn(host string, port int, timeout time.Duration, useSSL bool, intensity int) (*ServiceResult, error) {

	// Check excluded ports (nmap Exclude directive - e.g. printer ports 9100-9107)
	if db.ExcludePorts[port] {
		return nil, fmt.Errorf("port %d is excluded from service scanning", port)
	}

	queue := db.buildProbeQueue(port, useSSL, intensity)
	if len(queue) == 0 {
		return nil, fmt.Errorf("no probes available for port %d (intensity=%d)", port, intensity)
	}

	if db.Debug {
		fmt.Fprintf(os.Stderr, "[DEBUG] Queue built: %d probes for port %d (SSL=%v, intensity=%d)\n", len(queue), port, useSSL, intensity)
		for i, p := range queue {
			log.Printf("[DEBUG]   [%d] %s (rarity=%d)\n", i+1, p.Name, p.Rarity)
		}
	}

	var bestResult *ServiceResult
	var nullProbeResponse string        // Keep the NULL probe response
	var firstTLSInfo *TLSConnectionInfo // Keep the TLS info from the first successful connection
	probedCount := 0
	consecutiveNullResults := 0
	maxConsecutiveNullResults := 20 // Reduced: test at most 15 consecutive probes without a match
	consecutiveConnErrors := 0
	maxConsecutiveConnErrors := 3 // Stop after 3 consecutive connection errors
	probesAfterProduct := 0       // Counter of probes tested after finding a product

	if db.Debug {
		log.Printf("[DEBUG] Starting probe loop with %d probes", len(queue))
	}

	// Track softmatch service for serviceIsPossible filtering (nmap DEV-2)
	softMatchService := ""

	// Test each probe with its own connection
	for _, probe := range queue {
		// After a softmatch, only test probes that have a match pattern for the
		// detected service (nmap's serviceIsPossible optimization).
		// Skip this filter at intensity >= 9 (comprehensive mode, like nmap).
		if softMatchService != "" && intensity < 9 {
			if !probe.serviceIsPossible(softMatchService) {
				if db.Debug {
					log.Printf("[DEBUG]   Skipping probe %s: no match for service %q (serviceIsPossible=false)\n", probe.Name, softMatchService)
				}
				continue
			}
		}
		if db.Debug {
			log.Printf("[DEBUG] Testing probe: %s\n", probe.Name)
		}

		startTime := time.Now()
		conn, tlsInfo, err := connectToPort(host, port, timeout, useSSL)
		if err != nil {
			if db.Debug {
				log.Printf("[DEBUG]   Connection failed: %v\n", err)
			}

			// Fail-fast: immediately detect whether the port is closed (only connection refused)
			if isPortClosedError(err) {
				consecutiveConnErrors++
				if consecutiveConnErrors >= maxConsecutiveConnErrors {
					if db.Debug {
						log.Printf("[DEBUG] Port closed detected after %d attempts\n", consecutiveConnErrors)
					}
					if bestResult != nil {
						attachTLSInfo(bestResult, firstTLSInfo, host, port)
						return bestResult, nil
					}
					return nil, fmt.Errorf("port closed: %w", err)
				}
			} else {
				consecutiveConnErrors++
			}

			consecutiveNullResults++

			// If too many consecutive connection errors, the port is probably closed/filtered
			if consecutiveConnErrors >= maxConsecutiveConnErrors {
				if db.Debug {
					log.Printf("[DEBUG] Stopping: %d consecutive connection errors\n", consecutiveConnErrors)
				}
				// If we already have a result, return it, otherwise error
				if bestResult != nil {
					attachTLSInfo(bestResult, firstTLSInfo, host, port)
					return bestResult, nil
				}
				return nil, fmt.Errorf("port appears closed or filtered after %d connection failures", consecutiveConnErrors)
			}

			if consecutiveNullResults >= maxConsecutiveNullResults {
				break
			}
			continue
		}

		// Connection successful: reset the connection error counter
		consecutiveConnErrors = 0

		// Save the TLS info from the first successful connection
		if tlsInfo != nil && firstTLSInfo == nil {
			firstTLSInfo = tlsInfo
			if db.Debug {
				log.Printf("[DEBUG] TLS Info captured: Version=0x%04x, Cipher=0x%04x, Certs=%d\n",
					tlsInfo.TLSVersion, tlsInfo.CipherSuite, len(tlsInfo.CertificatesPEM))
			}
		}

		result, rawResp := db.testSingleProbe(conn, probe, useSSL, host)

		// Save the NULL probe response
		if probe.Name == "NULL" && rawResp != "" {
			nullProbeResponse = rawResp
		}

		conn.Close()
		probedCount++
		elapsed := time.Since(startTime)

		if db.Debug {
			if result != nil {
				log.Printf("[DEBUG]   ✓ Match found: %s (soft=%v, elapsed=%v)\n", result.Service, result.isSoft, elapsed)
			} else {
				log.Printf("[DEBUG]   ✗ No match (elapsed=%v)\n", elapsed)
			}
		}

		if result != nil {
			consecutiveNullResults = 0 // Reset the counter

			// Track softmatch service for serviceIsPossible filtering
			if result.isSoft && softMatchService == "" {
				softMatchService = result.Service
			}

			// Hard match with Product AND Version -> perfect match, we can stop
			if !result.isSoft && result.Product != "" && result.Version != "" {
				result.NullProbeResponse = nullProbeResponse
				attachTLSInfo(result, firstTLSInfo, host, port)
				return result, nil
			}

			// Remember the best result
			if bestResult == nil {
				bestResult = result
			} else if !result.isSoft && bestResult.isSoft {
				// Hard match beats soft match
				bestResult = result
			} else if !result.isSoft && !bestResult.isSoft {
				// Between two hard matches, take the one with the most info
				if result.Product != "" && bestResult.Product == "" {
					// New result has a product, the old one does not
					bestResult = result
				} else if result.Product != "" && result.Version != "" && bestResult.Version == "" {
					// New result has product + version, the old one just product
					bestResult = result
				}
			}
		} else {
			consecutiveNullResults++
			// If too many consecutive null results, stop
			if consecutiveNullResults >= maxConsecutiveNullResults {
				break
			}
		}

		// Early-stop checks (after updating bestResult)

		// If bestResult already has a hard match with product, count the following probes
		// Exception: if the service is just "ssl" without a product, continue to find the application service
		if bestResult != nil && !bestResult.isSoft && bestResult.Product != "" {
			probesAfterProduct++
			// Fast return after 2 additional probes instead of 5
			if probesAfterProduct >= 2 {
				bestResult.NullProbeResponse = nullProbeResponse
				attachTLSInfo(bestResult, firstTLSInfo, host, port)
				return bestResult, nil
			}
		} else if bestResult != nil && !bestResult.isSoft && bestResult.Service == "ssl" && bestResult.Product == "" {
			// Generic SSL service detected: continue to find the application service (https, imaps, etc)
			// Do not increment probesAfterProduct to give more chance to the following probes
			if probedCount >= 10 {
				bestResult.NullProbeResponse = nullProbeResponse
				attachTLSInfo(bestResult, firstTLSInfo, host, port)
				return bestResult, nil
			}
		}

		// If we have an HTTP/HTTPS soft match, return after a few probes
		// Note: We no longer rely on the port but only on the detected service
		if bestResult != nil && bestResult.isSoft &&
			(bestResult.Service == "http" || bestResult.Service == "https" || bestResult.Service == "ssl/http") &&
			probedCount >= 3 {
			bestResult.NullProbeResponse = nullProbeResponse
			attachTLSInfo(bestResult, firstTLSInfo, host, port)
			return bestResult, nil
		}

		// If we only have a non-HTTP soft match and have tested at least 3 probes, stop
		if bestResult != nil && bestResult.isSoft && probedCount >= 3 {
			bestResult.NullProbeResponse = nullProbeResponse
			attachTLSInfo(bestResult, firstTLSInfo, host, port)
			return bestResult, nil
		}

		// Absolute limit: test at most 30 probes
		if probedCount >= 30 {
			break
		}
	}

	// Return the best result found
	if bestResult != nil {
		bestResult.NullProbeResponse = nullProbeResponse
		attachTLSInfo(bestResult, firstTLSInfo, host, port)
		return bestResult, nil
	}

	// Fallback: use nmap-services if the port is known
	// This simulates nmap's behavior of returning the port's default service
	// Marked as "uncertain" because based only on the port, without a probe match
	if serviceName, exists := db.PortServices[port]; exists {
		fallbackResult := &ServiceResult{
			Service:           serviceName,
			Product:           "",
			Version:           "",
			Info:              "",
			Probe:             "nmap-services",
			isSoft:            true,
			Uncertain:         true, // Uncertainty marker (equivalent to nmap's "?")
			RawResponse:       "",
			NullProbeResponse: nullProbeResponse,
		}
		attachTLSInfo(fallbackResult, firstTLSInfo, host, port)
		return fallbackResult, nil
	}

	return nil, fmt.Errorf("no matching service found")
}

// testSingleProbe tests a single probe on a connection
// Returns (result, rawResponse)
func (db *ProbeDB) testSingleProbe(conn net.Conn, probe *Probe, useSSL bool, host string) (*ServiceResult, string) {
	var response []byte

	// NULL probe: do not send any data
	if probe.Name == "NULL" {
		waitTime := time.Duration(probe.TotalWaitMS) * time.Millisecond
		if waitTime == 0 {
			waitTime = 3 * time.Second
		}
		conn.SetReadDeadline(time.Now().Add(waitTime))
		readStart := time.Now()
		buf := make([]byte, 8192)
		n, readErr := conn.Read(buf)
		readDuration := time.Since(readStart)
		if n > 0 {
			response = buf[:n]
		} else if readErr != nil {
			// tcpwrapped detection (nmap behavior):
			// If the connection closed (EOF/reset) before tcpwrappedms without sending
			// any data, the port is tcpwrapped (a TCP wrapper rejected the connection).
			tcpwrappedTimeout := time.Duration(probe.TCPWrappedMS) * time.Millisecond
			if tcpwrappedTimeout == 0 {
				tcpwrappedTimeout = 2 * time.Second
			}
			isEOF := readErr == io.EOF || strings.Contains(readErr.Error(), "connection reset")
			if isEOF && readDuration < tcpwrappedTimeout {
				return &ServiceResult{
					Service: "tcpwrapped",
					Probe:   "NULL",
					isSoft:  false,
				}, ""
			}
		}
	} else {
		// Send the probe
		if len(probe.ProbeString) > 0 {
			conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
			if _, err := conn.Write(probe.ProbeString); err != nil {
				return nil, ""
			}
		}

		// Read the response with an optimized timeout
		waitTime := time.Duration(probe.TotalWaitMS) * time.Millisecond
		if waitTime == 0 {
			waitTime = 3 * time.Second
		}

		// Optimization: reduce the timeout for rare probes in SSL mode
		// These probes are unlikely to match on standard SSL/TLS services
		if useSSL && probe.Rarity > 3 {
			maxWait := 2 * time.Second
			if waitTime > maxWait {
				waitTime = maxWait
			}
		}

		response = readResponse(conn, waitTime)
	}

	rawResponse := string(response)

	if len(response) == 0 {
		return nil, ""
	}

	// Debug: display the raw response if available
	if db.Debug && len(response) > 0 {
		log.Printf("[DEBUG]   Raw response (%d bytes): %q\n", len(response), string(response[:min(len(response), 200)]))
	}

	// Test the matches
	if result := db.testMatches(probe, response, ""); result != nil {
		result.Probe = probe.Name

		// If in SSL, fix the service name
		if useSSL {
			switch result.Service {
			case "http", "ssl/http":
				result.Service = "https"
			case "imap":
				result.Service = "imaps"
			case "pop3":
				result.Service = "pop3s"
			case "smtp":
				result.Service = "smtps"
			}
		}

		// For HTTP/HTTPS, only keep the headers
		// Note: Wappalyzer + favicon moved to enrichment for better performance
		if result.Service == "http" || result.Service == "https" {
			result.RawResponse = extractHTTPHeaders(response)
		} else {
			result.RawResponse = string(response)
		}
		return result, rawResponse
	}

	// Test the fallbacks
	if result := db.testFallbacks(probe, response); result != nil {
		result.Probe = probe.Name + " (fallback)"

		// If in SSL, fix the service name
		if useSSL {
			switch result.Service {
			case "http", "ssl/http":
				result.Service = "https"
			case "imap":
				result.Service = "imaps"
			case "pop3":
				result.Service = "pop3s"
			case "smtp":
				result.Service = "smtps"
			}
		}

		if result.Service == "http" || result.Service == "https" {
			result.RawResponse = extractHTTPHeaders(response)
		} else {
			result.RawResponse = string(response)
		}
		return result, rawResponse
	}

	// Generic fallback for HTTP only (standard nmap behavior)
	responseStr := string(response)
	if strings.HasPrefix(responseStr, "HTTP/") {
		service := "http"
		if useSSL {
			service = "https"
		}

		// Note: An HTTP→HTTPS redirect (301/302 with Location: https://) does NOT mean
		// that the port uses SSL/TLS. It is just a normal HTTP server that redirects.
		// The "ssl/http" classification is removed because it caused incorrect
		// TLS connection attempts on standard HTTP ports.

		// Return a soft match without product
		// Nmap does the same when no pattern matches
		return &ServiceResult{
			Service:     service,
			Product:     "",
			Version:     "",
			Probe:       "generic",
			isSoft:      true,
			RawResponse: extractHTTPHeaders(response),
		}, rawResponse
	}

	return nil, rawResponse
}

// GrabPort is a utility function to scan a full port
func (db *ProbeDB) GrabPort(host string, port int, timeout time.Duration, useSSL bool, intensity int) (*ServiceResult, error) {
	return db.ProbeServiceMultiConn(host, port, timeout, useSSL, intensity)
}

// Scan scans a port with SSL auto-detection and global timeout
var (
	probeDB     *ProbeDB
	probeDBOnce sync.Once
	probeDBErr  error

	// Global WorkerPool singleton for auto-tuning
	globalPool     *WorkerPool
	globalPoolOnce sync.Once
	globalPoolErr  error
)

// getProbeDB returns a singleton ProbeDB instance using embedded nmap files
func getProbeDB() (*ProbeDB, error) {
	probeDBOnce.Do(func() {
		// Use the nmap files embedded in the binary
		probeDB, probeDBErr = LoadProbes(GetEmbeddedProbesReader())
		if probeDBErr == nil {
			probeDB.LoadServices(GetEmbeddedServicesReader())
			probeDB.Debug = false // Disable debug
		}
	})
	return probeDB, probeDBErr
}

// getGlobalPool returns the global singleton pool with auto-tuning
func getGlobalPool() (*WorkerPool, error) {
	globalPoolOnce.Do(func() {
		config := DefaultWorkerPoolConfig()
		config.AutoTune = true
		globalPool, globalPoolErr = NewWorkerPool(config)
	})
	return globalPool, globalPoolErr
}

// Grab is the main function to perform a service scan
// This is the function to use from another library
func Grab(host string, port int) (*ServiceResult, error) {
	// ProbeTimeout: 3s, Intensity: 5 (reduced from 7 to avoid long timeouts), GlobalTimeout: 30s
	return GrabWithOptions(host, port, 3*time.Second, 5, 30*time.Second, false)
}

// GrabWithOptions scans a port with custom options
func GrabWithOptions(host string, port int, probeTimeout time.Duration, intensity int, globalTimeout time.Duration, debug bool) (*ServiceResult, error) {
	// Use the global pool with auto-tuning
	pool, err := getGlobalPool()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize worker pool: %w", err)
	}

	// Create a channel to receive the result
	resultChan := make(chan ScanResult, 1)

	// Create a request for the pool
	req := ScanRequest{
		Host:          host,
		Port:          port,
		ProbeTimeout:  probeTimeout,
		Intensity:     intensity,
		GlobalTimeout: globalTimeout,
		Debug:         debug,
		ResultChan:    resultChan,
	}

	// Submit to the pool
	if err := pool.Submit(req); err != nil {
		return nil, err
	}

	// Wait for the result on our dedicated channel
	select {
	case result := <-resultChan:
		return result.Result, result.Error
	case <-time.After(globalTimeout + 5*time.Second): // +5s to avoid race condition
		return nil, fmt.Errorf("scan timeout after %v", globalTimeout)
	}
}

// GetProbesByPort returns the relevant probes for a given port
func (db *ProbeDB) GetProbesByPort(port int, ssl bool) []*Probe {
	var probes []*Probe

	for _, probe := range db.Probes {
		portList := probe.Ports
		if ssl {
			portList = probe.SSLPorts
		}

		if containsPort(portList, port) {
			probes = append(probes, probe)
		}
	}

	// Sort by rarity
	sort.Slice(probes, func(i, j int) bool {
		return probes[i].Rarity < probes[j].Rarity
	})

	return probes
}
