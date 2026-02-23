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

// Probe représente un probe nmap
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
	FallbackProbes []*Probe // Pointeurs précompilés vers les probes de fallback
}

// Match représente une règle de matching
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

// ServiceResult contient le résultat de la détection
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
	Uncertain         bool               // Service deviné depuis nmap-services sans probe match
	RawResponse       string
	NullProbeResponse string             // Réponse brute du probe NULL (pour analyse)
	TLSVersion        uint16             // TLS version (ex: 0x0303 = TLS 1.2)
	CipherSuite       uint16             // Cipher suite negotiated
	ServerName        string             // SNI server name
	Certificates      []*tls.Certificate // Raw certificates chain (DEPRECATED - use CertificatesPEM)
	CertificatesPEM   []string           // PEM-encoded certificates
	JARMFingerprint   string             // JARM TLS fingerprint
}

/**
// String formate le résultat comme nmap
func (r *ServiceResult) String() string {
	var parts []string

	if r.Product != "" {
		parts = append(parts, r.Product)
	}
	if r.Version != "" {
		parts = append(parts, r.Version)
	}

	result := strings.Join(parts, " ")

	// Ajouter l'info entre parenthèses si présente
	if r.Info != "" {
		if result != "" {
			result += " (" + r.Info + ")"
		} else {
			result = r.Info
		}
	}

	return result
}

// FullString retourne le format complet incluant le service
func (r *ServiceResult) FullString() string {
	version := r.String()
	if version != "" {
		return r.Service + " " + version
	}
	return r.Service
}
**/
// ProbeDB contient tous les probes
type ProbeDB struct {
	Probes       []*Probe
	NullProbe    *Probe
	ExcludePorts map[int]bool
	PortServices map[int]string // Mapping port->service depuis nmap-services
	Debug        bool           // Mode debug pour afficher les probes testés
}

// LoadProbes charge le fichier nmap-service-probes depuis un io.Reader
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
					// Validation comme nmap : entre 100 et 300000 ms
					if t < 100 || t > 300000 {
						log.Printf("Warning: totalwaitms must be between 100 and 300000, got %d (using default)\n", t)
						currentProbe.TotalWaitMS = 5000
					} else {
						currentProbe.TotalWaitMS = t
					}
				}
			} else if strings.HasPrefix(line, "tcpwrappedms ") {
				if t, err := strconv.Atoi(strings.TrimSpace(line[13:])); err == nil {
					// Validation comme nmap : entre 100 et 300000 ms
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

	// Compiler les fallbacks (comme nmap)
	db.compileFallbacks()

	return db, scanner.Err()
}

// LoadServices charge le fichier nmap-services depuis un io.Reader pour le mapping port->service
func (db *ProbeDB) LoadServices(reader io.Reader) error {
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Ignorer les lignes vides et commentaires
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Format: service_name port/protocol frequency [comment]
		// Exemple: irc	6667/tcp	0.000652	# Internet Relay Chat
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		serviceName := fields[0]
		portProto := fields[1]

		// Parser port/protocol
		parts := strings.Split(portProto, "/")
		if len(parts) != 2 {
			continue
		}

		port, err := strconv.Atoi(parts[0])
		if err != nil {
			continue
		}

		protocol := parts[1]

		// Ne garder que TCP pour l'instant
		if protocol == "tcp" {
			// Si le port n'a pas déjà un service, l'ajouter
			if _, exists := db.PortServices[port]; !exists {
				db.PortServices[port] = serviceName
			}
		}
	}

	return scanner.Err()
}

// compileFallbacks précompile les fallbacks en pointeurs (comme nmap)
func (db *ProbeDB) compileFallbacks() {
	// Cas spécial : NULL probe
	if db.NullProbe != nil {
		db.NullProbe.FallbackProbes = append(db.NullProbe.FallbackProbes, db.NullProbe)
	}

	for _, probe := range db.Probes {
		// Toujours commencer par le probe lui-même
		probe.FallbackProbes = append(probe.FallbackProbes, probe)

		// Ajouter les fallbacks spécifiés dans la directive
		for _, fbName := range probe.Fallbacks {
			fbProbe := db.getProbeByName(fbName)
			if fbProbe != nil {
				probe.FallbackProbes = append(probe.FallbackProbes, fbProbe)
			}
		}

		// Pour TCP : ajouter NULL probe à la fin (automatique)
		if probe.Protocol == "TCP" && db.NullProbe != nil {
			// Éviter de dupliquer si le probe est lui-même NULL
			if probe.Name != "NULL" {
				probe.FallbackProbes = append(probe.FallbackProbes, db.NullProbe)
			}
		}
	}
}

// getProbeByName trouve un probe par son nom
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

	// Validation stricte des flags (comme nmap : uniquement 'i' et 's')
	for _, flag := range flags {
		if flag != 'i' && flag != 's' {
			// Nmap rejette les autres flags (notamment 'm')
			return nil
		}
	}

	// Construire les options PCRE en combinant les flags
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

	// NE PAS unescape les patterns - ils sont déjà en format regex correct
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

		// Retirer le '/' final si présent
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
			// Terminer la partie actuelle avec le '/'
			current.WriteByte(info[i])
			if s := current.String(); s != "" {
				parts = append(parts, s)
			}
			current.Reset()
			// Sauter l'espace
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
				// Nmap rejette les séquences octales (nombres)
				if (s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'z') || (s[i] >= 'A' && s[i] <= 'Z') {
					// Caractère alphanumérique après '\' : invalide (comme nmap)
					// On retourne la chaîne telle quelle en cas d'erreur
					return s
				}
				// Autres caractères : copie tel quel (pour \", \|, etc.)
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

// buildProbeQueue construit la queue de probes selon l'algorithme nmap.
// Suit les 3 etats stricts de nmap (service_scan.cc nextProbe()):
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
	// Chercher la fin des headers HTTP (double CRLF)
	dataStr := string(data)

	// HTTP utilise \r\n\r\n pour séparer headers et body
	if idx := strings.Index(dataStr, "\r\n\r\n"); idx != -1 {
		return dataStr[:idx+4] // Inclure le double CRLF
	}
	// Fallback pour \n\n
	if idx := strings.Index(dataStr, "\n\n"); idx != -1 {
		return dataStr[:idx+2]
	}

	// Si pas de séparateur trouvé, retourner tout (probablement juste les headers)
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
			// Après la première lecture, utiliser un timeout court pour les données additionnelles
			conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		}
		if err != nil {
			break
		}
	}

	return response
}

// safeRegexMatch exécute un match regex avec timeout pour éviter les attaques ReDoS
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
		// Timeout : possible attaque ReDoS
		return false, nil
	}
}

func (db *ProbeDB) testMatches(probe *Probe, response []byte, filterService string) *ServiceResult {
	// Limiter la taille de la réponse pour éviter les regex trop longues
	maxMatchSize := 16384
	matchResponse := response
	if len(response) > maxMatchSize {
		matchResponse = response[:maxMatchSize]
	}
	responseStr := string(matchResponse)

	// Comportement nmap: retourner le PREMIER match trouvé (first-match-wins)
	// au lieu de collecter tous les matches et choisir le meilleur score
	for _, match := range probe.Matches {
		// Si on filtre par service, vérifier la compatibilité
		if filterService != "" && !match.serviceMatches(filterService) {
			continue
		}

		// Utiliser safeRegexMatch avec timeout de 5 secondes (protection ReDoS)
		matched, groups := safeRegexMatch(match.Pattern, responseStr, 5*time.Second)
		if !matched {
			continue
		}

		// Si pas de groupes capturés, utiliser le match complet
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

		// Debug: afficher les détails du match
		if db.Debug {
			log.Printf("[DEBUG-MATCH] service=%s soft=%v product_tpl=%q product=%q version=%q",
				result.Service, result.isSoft, match.Product, result.Product, result.Version)
		}

		// Fix: forcer soft match pour HTTP sans Product (comportement nmap)
		// Un match HTTP sans Product est considéré comme générique/soft
		if !result.isSoft && result.Product == "" {
			if result.Service == "http" || result.Service == "https" || result.Service == "ssl/http" {
				result.isSoft = true
			}
		}

		// FIRST-MATCH-WINS: retourner immédiatement le premier match trouvé
		return result
	}

	// Aucun match trouvé
	return nil
}

func (db *ProbeDB) testFallbacks(probe *Probe, response []byte) *ServiceResult {
	// Utiliser les fallbacks précompilés (plus rapide que la recherche par nom)
	for _, fbProbe := range probe.FallbackProbes {
		// Ignorer le probe lui-même (déjà testé)
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
	// Un résultat est considéré soft si peu d'infos
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
			// Trouver la fin de la variable
			varStart := i
			i++

			// Simple $N (un seul chiffre)
			if s[i] >= '1' && s[i] <= '9' {
				num := int(s[i] - '0')
				if num < len(groups) {
					result.WriteString(groups[num])
				}
				i++
				continue
			}

			// Commandes avancées : $P(), $SUBST(), $I()
			if s[i] >= 'A' && s[i] <= 'Z' {
				cmdStart := i
				// Trouver la fin du nom de commande
				for i < len(s) && s[i] >= 'A' && s[i] <= 'Z' {
					i++
				}
				cmdName := s[cmdStart:i]

				// Doit être suivi de '('
				if i >= len(s) || s[i] != '(' {
					// Pas une commande valide, copier tel quel
					result.WriteString(s[varStart:i])
					continue
				}

				// Trouver la parenthèse fermante
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
					// Parenthèses non fermées
					result.WriteString(s[varStart:])
					break
				}

				// Extraire les arguments
				argsStr := s[parenStart+1 : i-1]
				expansion := processSubstCommand(cmdName, argsStr, groups)
				result.WriteString(expansion)
				continue
			}

			// Caractère invalide après $
			result.WriteByte('$')
		} else {
			result.WriteByte(s[i])
			i++
		}
	}

	return result.String()
}

// processSubstCommand traite les commandes de substitution avancées
func processSubstCommand(cmd string, argsStr string, groups []string) string {
	switch cmd {
	case "P":
		// $P(N) - filtre caractères imprimables
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

// substP filtre les caractères imprimables
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

// substSUBST effectue un remplacement de chaîne
func substSUBST(argsStr string, groups []string) string {
	// Parser: N,"find","replace"
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

// substI convertit des bytes binaires en entier
func substI(argsStr string, groups []string) string {
	// Parser: N,"<"|">"
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

// parseSubstArgs parse les arguments séparés par des virgules, gérant les chaînes quotées
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
			// Ajouter même si vide (pour supporter les strings vides comme "")
			args = append(args, strings.TrimSpace(current.String()))
			current.Reset()
			continue
		}

		current.WriteByte(ch)
	}

	// Toujours ajouter le dernier argument, même s'il est vide
	args = append(args, strings.TrimSpace(current.String()))

	return args
}

// ScanPortAuto scanne un port avec détection SSL basée sur le numéro de port
func (db *ProbeDB) ScanPortAuto(host string, port int, timeout time.Duration, intensity int) (*ServiceResult, error) {
	// Ports SSL standards : essayer directement en SSL
	sslPorts := map[int]bool{
		443: true, 8443: true, 9443: true, 4443: true, // HTTPS
		465: true, 587: true, 993: true, 995: true, // Email SSL
		636: true, 3269: true, // LDAPS
		989: true, 990: true, // FTPS
		5986: true, 8531: true, // WinRM HTTPS
	}

	// Si c'est un port SSL standard, essayer directement en SSL
	if sslPorts[port] {
		result, err := db.GrabPort(host, port, timeout, true, intensity)
		// Si succès, retourner
		if err == nil && result != nil {
			return result, nil
		}
		// Si échec sur port SSL standard, fallback en non-SSL
		return db.GrabPort(host, port, timeout, false, intensity)
	}

	// Pour les autres ports : essayer d'abord sans SSL
	result, err := db.GrabPort(host, port, timeout, false, intensity)

	// Si le service détecté commence par "ssl/", cela signifie que le service nécessite SSL
	// (nmap-service-probes convention: ssl/http, ssl/imap, etc.)
	// Dans ce cas, réessayer automatiquement en SSL
	if result != nil && strings.HasPrefix(result.Service, "ssl/") {
		resultSSL, errSSL := db.GrabPort(host, port, timeout, true, intensity)
		if errSSL == nil && resultSSL != nil {
			return resultSSL, nil
		}
		// Si échec SSL, convertir quand même ssl/* en service SSL approprié
		// pour assurer la cohérence dans la base de données
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

	// Si succès avec un résultat hard et product, retourner
	if result != nil && !result.isSoft && result.Product != "" {
		return result, nil
	}

	// Si soft match HTTP sur port HTTP standard, ne pas retry SSL (optimisation nmap)
	if result != nil && result.isSoft &&
		(result.Service == "http" || result.Service == "https") &&
		(port == 80 || port == 8080 || port == 8000 || port == 8888) {
		return result, nil
	}

	// Si pas de résultat ou résultat soft, réessayer en SSL
	// Cela permet de détecter les services SSL sur ports non-standards
	resultSSL, errSSL := db.GrabPort(host, port, timeout, true, intensity)
	if errSSL == nil && resultSSL != nil {
		return resultSSL, nil
	}

	// Si scan SSL a échoué mais scan non-SSL a réussi, retourner le résultat non-SSL
	if result != nil {
		return result, err
	}

	// Sinon retourner le résultat SSL
	return resultSSL, errSSL
}

// isPortClosedError détecte rapidement si un port est fermé/inaccessible
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

// TLSConnectionInfo contient les informations de la connexion TLS
type TLSConnectionInfo struct {
	Conn            net.Conn
	TLSVersion      uint16
	CipherSuite     uint16
	ServerName      string
	CertificatesPEM []string
}

// connectToPort ouvre une connexion TCP ou TLS
// Retourne (conn, tlsInfo, error)
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

		// Extraire les informations TLS
		state := tlsConn.ConnectionState()
		tlsInfo := &TLSConnectionInfo{
			Conn:            tlsConn,
			TLSVersion:      state.Version,
			CipherSuite:     state.CipherSuite,
			ServerName:      state.ServerName,
			CertificatesPEM: make([]string, 0, len(state.PeerCertificates)),
		}

		// Convertir les certificats en PEM
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

// EncodeCertToPEM encode un certificat DER en PEM
func EncodeCertToPEM(derBytes []byte) string {
	// Format PEM standard
	encoded := "-----BEGIN CERTIFICATE-----\n"
	// Base64 encode avec wrapping à 64 caractères
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

// Base64Encode encode en base64 standard
func Base64Encode(data []byte) string {
	const base64Table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var result strings.Builder
	n := len(data)

	for i := 0; i < n; i += 3 {
		// Lire jusqu'à 3 bytes
		b1 := data[i]
		var b2, b3 byte
		if i+1 < n {
			b2 = data[i+1]
		}
		if i+2 < n {
			b3 = data[i+2]
		}

		// Convertir en 4 caractères base64
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

// attachTLSInfo attache les informations TLS à un résultat et calcule JARM si TLS détecté
func attachTLSInfo(result *ServiceResult, tlsInfo *TLSConnectionInfo, host string, port int) {
	if result == nil {
		return
	}

	// Si on a déjà des infos TLS, les utiliser
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

	// Si on n'a pas d'info TLS mais qu'un service SSL a été détecté
	// (via un probe brut comme SSLSessionReq), faire une connexion TLS réelle
	// pour extraire les certificats et calculer JARM
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

// isSSLService détecte si un service utilise SSL/TLS
func isSSLService(service string) bool {
	// Services SSL/TLS courants
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

// ProbeServiceMultiConn teste plusieurs probes en ouvrant une connexion par probe
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
	var nullProbeResponse string        // Conserver la réponse du probe NULL
	var firstTLSInfo *TLSConnectionInfo // Conserver les infos TLS de la première connexion réussie
	probedCount := 0
	consecutiveNullResults := 0
	maxConsecutiveNullResults := 20 // Réduit : tester maximum 15 probes consécutifs sans match
	consecutiveConnErrors := 0
	maxConsecutiveConnErrors := 3 // Arrêter après 3 erreurs de connexion consécutives
	probesAfterProduct := 0       // Compteur de probes testés après avoir trouvé un produit

	if db.Debug {
		log.Printf("[DEBUG] Starting probe loop with %d probes", len(queue))
	}

	// Track softmatch service for serviceIsPossible filtering (nmap DEV-2)
	softMatchService := ""

	// Tester chaque probe avec sa propre connexion
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

			// Fail-fast: détecter immédiatement si le port est fermé (uniquement connection refused)
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

			// Si trop d'erreurs de connexion consécutives, le port est probablement fermé/filtré
			if consecutiveConnErrors >= maxConsecutiveConnErrors {
				if db.Debug {
					log.Printf("[DEBUG] Stopping: %d consecutive connection errors\n", consecutiveConnErrors)
				}
				// Si on a déjà un résultat, le retourner, sinon erreur
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

		// Connexion réussie : réinitialiser le compteur d'erreurs de connexion
		consecutiveConnErrors = 0

		// Sauvegarder les infos TLS de la première connexion réussie
		if tlsInfo != nil && firstTLSInfo == nil {
			firstTLSInfo = tlsInfo
			if db.Debug {
				log.Printf("[DEBUG] TLS Info captured: Version=0x%04x, Cipher=0x%04x, Certs=%d\n",
					tlsInfo.TLSVersion, tlsInfo.CipherSuite, len(tlsInfo.CertificatesPEM))
			}
		}

		result, rawResp := db.testSingleProbe(conn, probe, useSSL, host)

		// Sauvegarder la réponse du probe NULL
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
			consecutiveNullResults = 0 // Réinitialiser le compteur

			// Track softmatch service for serviceIsPossible filtering
			if result.isSoft && softMatchService == "" {
				softMatchService = result.Service
			}

			// Hard match avec Product ET Version -> match parfait, on peut arrêter
			if !result.isSoft && result.Product != "" && result.Version != "" {
				result.NullProbeResponse = nullProbeResponse
				attachTLSInfo(result, firstTLSInfo, host, port)
				return result, nil
			}

			// Mémoriser le meilleur résultat
			if bestResult == nil {
				bestResult = result
			} else if !result.isSoft && bestResult.isSoft {
				// Hard match bat soft match
				bestResult = result
			} else if !result.isSoft && !bestResult.isSoft {
				// Entre deux hard matches, prendre celui avec le plus d'infos
				if result.Product != "" && bestResult.Product == "" {
					// Nouveau résultat a un produit, l'ancien non
					bestResult = result
				} else if result.Product != "" && result.Version != "" && bestResult.Version == "" {
					// Nouveau résultat a produit + version, l'ancien juste produit
					bestResult = result
				}
			}
		} else {
			consecutiveNullResults++
			// Si trop de résultats nuls consécutifs, arrêter
			if consecutiveNullResults >= maxConsecutiveNullResults {
				break
			}
		}

		// Vérifications d'arrêt anticipé (après mise à jour de bestResult)

		// Si bestResult a déjà un hard match avec product, compter les probes suivants
		// Exception: si le service est juste "ssl" sans produit, continuer pour trouver le service applicatif
		if bestResult != nil && !bestResult.isSoft && bestResult.Product != "" {
			probesAfterProduct++
			// Retour rapide après 2 probes supplémentaires au lieu de 5
			if probesAfterProduct >= 2 {
				bestResult.NullProbeResponse = nullProbeResponse
				attachTLSInfo(bestResult, firstTLSInfo, host, port)
				return bestResult, nil
			}
		} else if bestResult != nil && !bestResult.isSoft && bestResult.Service == "ssl" && bestResult.Product == "" {
			// Service SSL générique détecté : continuer pour trouver le service applicatif (https, imaps, etc)
			// Ne pas incrémenter probesAfterProduct pour laisser plus de chance aux probes suivants
			if probedCount >= 10 {
				bestResult.NullProbeResponse = nullProbeResponse
				attachTLSInfo(bestResult, firstTLSInfo, host, port)
				return bestResult, nil
			}
		}

		// Si on a un soft match HTTP/HTTPS, retourner après quelques probes
		// Note: On ne se base plus sur le port mais uniquement sur le service détecté
		if bestResult != nil && bestResult.isSoft &&
			(bestResult.Service == "http" || bestResult.Service == "https" || bestResult.Service == "ssl/http") &&
			probedCount >= 3 {
			bestResult.NullProbeResponse = nullProbeResponse
			attachTLSInfo(bestResult, firstTLSInfo, host, port)
			return bestResult, nil
		}

		// Si on n'a qu'un soft match non-HTTP et qu'on a testé 3 probes minimum, arrêter
		if bestResult != nil && bestResult.isSoft && probedCount >= 3 {
			bestResult.NullProbeResponse = nullProbeResponse
			attachTLSInfo(bestResult, firstTLSInfo, host, port)
			return bestResult, nil
		}

		// Limite absolue : tester au maximum 30 probes
		if probedCount >= 30 {
			break
		}
	}

	// Retourner le meilleur résultat trouvé
	if bestResult != nil {
		bestResult.NullProbeResponse = nullProbeResponse
		attachTLSInfo(bestResult, firstTLSInfo, host, port)
		return bestResult, nil
	}

	// Fallback : utiliser nmap-services si le port est connu
	// Cela simule le comportement de nmap qui retourne le service par défaut du port
	// Marqué comme "uncertain" car basé uniquement sur le port, sans probe match
	if serviceName, exists := db.PortServices[port]; exists {
		fallbackResult := &ServiceResult{
			Service:           serviceName,
			Product:           "",
			Version:           "",
			Info:              "",
			Probe:             "nmap-services",
			isSoft:            true,
			Uncertain:         true, // Marqueur d'incertitude (équivalent au "?" de nmap)
			RawResponse:       "",
			NullProbeResponse: nullProbeResponse,
		}
		attachTLSInfo(fallbackResult, firstTLSInfo, host, port)
		return fallbackResult, nil
	}

	return nil, fmt.Errorf("no matching service found")
}

// testSingleProbe teste un seul probe sur une connexion
// Retourne (result, rawResponse)
func (db *ProbeDB) testSingleProbe(conn net.Conn, probe *Probe, useSSL bool, host string) (*ServiceResult, string) {
	var response []byte

	// NULL probe : ne pas envoyer de données
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
		// Envoyer le probe
		if len(probe.ProbeString) > 0 {
			conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
			if _, err := conn.Write(probe.ProbeString); err != nil {
				return nil, ""
			}
		}

		// Lire la réponse avec timeout optimisé
		waitTime := time.Duration(probe.TotalWaitMS) * time.Millisecond
		if waitTime == 0 {
			waitTime = 3 * time.Second
		}

		// Optimisation : réduire le timeout pour les probes rares en mode SSL
		// Ces probes ont peu de chances de matcher sur des services SSL/TLS standards
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

	// Debug: afficher la réponse brute si disponible
	if db.Debug && len(response) > 0 {
		log.Printf("[DEBUG]   Raw response (%d bytes): %q\n", len(response), string(response[:min(len(response), 200)]))
	}

	// Tester les matches
	if result := db.testMatches(probe, response, ""); result != nil {
		result.Probe = probe.Name

		// Si on est en SSL, corriger le nom du service
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

		// Pour HTTP/HTTPS, ne garder que les headers
		// Note: Wappalyzer + favicon moved to enrichment for better performance
		if result.Service == "http" || result.Service == "https" {
			result.RawResponse = extractHTTPHeaders(response)
		} else {
			result.RawResponse = string(response)
		}
		return result, rawResponse
	}

	// Tester les fallbacks
	if result := db.testFallbacks(probe, response); result != nil {
		result.Probe = probe.Name + " (fallback)"

		// Si on est en SSL, corriger le nom du service
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

	// Fallback générique pour HTTP uniquement (comportement nmap standard)
	responseStr := string(response)
	if strings.HasPrefix(responseStr, "HTTP/") {
		service := "http"
		if useSSL {
			service = "https"
		}

		// Note: Une redirection HTTP→HTTPS (301/302 avec Location: https://) ne signifie PAS
		// que le port utilise SSL/TLS. C'est juste un serveur HTTP normal qui redirige.
		// La classification "ssl/http" est supprimée car elle causait des tentatives
		// incorrectes de connexion TLS sur des ports HTTP standards.

		// Retourner un soft match sans produit
		// Nmap fait pareil quand aucun pattern ne matche
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

// GrabPort est une fonction utilitaire pour scanner un port complet
func (db *ProbeDB) GrabPort(host string, port int, timeout time.Duration, useSSL bool, intensity int) (*ServiceResult, error) {
	return db.ProbeServiceMultiConn(host, port, timeout, useSSL, intensity)
}

// Scan scanne un port avec auto-détection SSL et timeout global
var (
	probeDB     *ProbeDB
	probeDBOnce sync.Once
	probeDBErr  error

	// Singleton WorkerPool global pour auto-tuning
	globalPool     *WorkerPool
	globalPoolOnce sync.Once
	globalPoolErr  error
)

// getProbeDB returns a singleton ProbeDB instance using embedded nmap files
func getProbeDB() (*ProbeDB, error) {
	probeDBOnce.Do(func() {
		// Utiliser les fichiers nmap embarqués dans le binaire
		probeDB, probeDBErr = LoadProbes(GetEmbeddedProbesReader())
		if probeDBErr == nil {
			probeDB.LoadServices(GetEmbeddedServicesReader())
			probeDB.Debug = false // Désactiver le debug
		}
	})
	return probeDB, probeDBErr
}

// getGlobalPool retourne le pool global singleton avec auto-tuning
func getGlobalPool() (*WorkerPool, error) {
	globalPoolOnce.Do(func() {
		config := DefaultWorkerPoolConfig()
		config.AutoTune = true
		globalPool, globalPoolErr = NewWorkerPool(config)
	})
	return globalPool, globalPoolErr
}

// Grab est la fonction principale pour effectuer un scan de service
// C'est la fonction à utiliser depuis une autre librairie
func Grab(host string, port int) (*ServiceResult, error) {
	// ProbeTimeout: 3s, Intensity: 5 (réduit de 7 pour éviter timeouts longs), GlobalTimeout: 30s
	return GrabWithOptions(host, port, 3*time.Second, 5, 30*time.Second, false)
}

// GrabWithOptions scanne un port avec des options personnalisées
func GrabWithOptions(host string, port int, probeTimeout time.Duration, intensity int, globalTimeout time.Duration, debug bool) (*ServiceResult, error) {
	// Utiliser le pool global avec auto-tuning
	pool, err := getGlobalPool()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize worker pool: %w", err)
	}

	// Créer un channel pour recevoir le résultat
	resultChan := make(chan ScanResult, 1)

	// Créer une requête pour le pool
	req := ScanRequest{
		Host:          host,
		Port:          port,
		ProbeTimeout:  probeTimeout,
		Intensity:     intensity,
		GlobalTimeout: globalTimeout,
		Debug:         debug,
		ResultChan:    resultChan,
	}

	// Soumettre au pool
	if err := pool.Submit(req); err != nil {
		return nil, err
	}

	// Attendre le résultat sur notre channel dédié
	select {
	case result := <-resultChan:
		return result.Result, result.Error
	case <-time.After(globalTimeout + 5*time.Second): // +5s pour éviter race condition
		return nil, fmt.Errorf("scan timeout after %v", globalTimeout)
	}
}

// GetProbesByPort retourne les probes pertinents pour un port donné
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

	// Trier par rareté
	sort.Slice(probes, func(i, j int) bool {
		return probes[i].Rarity < probes[j].Rarity
	})

	return probes
}
