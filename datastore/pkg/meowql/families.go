package meowql

import "strings"

// Protocol families group the many service-name variants that the scanner may
// label a port with (nmap service names, grabber module aliases) under a single
// canonical protocol. For example port 445 is reported as "microsoft-ds" and
// port 139 as "netbios-ssn", but both belong to the "smb" family.
//
// CURATED MAP — this is the single source of truth for family membership.
// It must be kept in sync (resynced periodically) with:
//   - the grabber enrichment module aliases (grabber/pkg/enrichment/modules/*)
//   - the nmap service names emitted by the fingerprint stage
//
// Rules:
//   - keys (canonical) and members are all lowercase
//   - the canonical name is always included as a member of its own family
//   - single-variant protocols don't need an entry: ProtocolFamily falls back to
//     [name] and FamilyOf falls back to the name itself when unknown.
var families = map[string][]string{
	// === explicitly required (smb and nfs are the user's reference examples) ===
	"smb":       {"smb", "microsoft-ds", "netbios-ssn", "cifs"},
	"nfs":       {"nfs", "rpcbind", "portmapper", "mountd", "nlockmgr", "nfs_acl", "rquotad"},
	"ftp":       {"ftp", "ftp-data"},
	"ssh":       {"ssh", "ssh2"},
	"smtp":      {"smtp", "smtps", "submission"},
	"http":      {"http", "https", "http-proxy", "http-alt", "https-alt"},
	"ldap":      {"ldap", "ldaps"},
	"pop3":      {"pop3", "pop3s"},
	"imap":      {"imap", "imaps"},
	"vnc":       {"vnc", "rfb"},
	"x11":       {"x11", "x-window", "xorg"},
	"xmpp":      {"xmpp", "jabber"},
	"amqp":      {"amqp", "rabbitmq"},
	"icecast":   {"icecast", "shoutcast"},
	"teamspeak": {"teamspeak", "ts3"},
	"lpd":       {"lpd", "printer"},
	"rdp":       {"rdp", "ms-wbt-server"},
	"mysql":     {"mysql", "mariadb"},
	"mssql":     {"ms-sql-s", "mssql", "ms-sql"},
	"dns":       {"dns", "domain"},

	// === reasonable extensions (well-known multi-name protocols) ===
	"mongodb": {"mongodb", "mongod"},
	"snmp":    {"snmp", "snmptrap"},
	"sip":     {"sip", "sips"},
	"mqtt":    {"mqtt", "secure-mqtt", "mqtts"},
	"coap":    {"coap", "coaps"},
	"irc":     {"irc", "ircs", "ircd"},
	"nntp":    {"nntp", "nntps", "snews"},
	"rtsp":    {"rtsp", "rtsps"},
	"afp":     {"afp", "afpovertcp"},
	"ntp":     {"ntp", "sntp"},
	"ajp13":   {"ajp13", "ajp"},
	"rsync":   {"rsync", "rsyncd"},
}

// memberToCanonical is the reverse index (member name -> canonical), built once
// at package init from the families map.
var memberToCanonical = buildMemberIndex()

func buildMemberIndex() map[string]string {
	idx := make(map[string]string)
	for canonical, members := range families {
		for _, m := range members {
			idx[strings.ToLower(m)] = canonical
		}
	}
	return idx
}

// ProtocolFamily returns all service-name members of the family identified by
// the given canonical name. The lookup is case-insensitive. If the name is not a
// known canonical it returns a single-element slice containing the (lowercased)
// name itself, so callers can always treat the result as "the set to match".
func ProtocolFamily(canonical string) []string {
	c := strings.ToLower(strings.TrimSpace(canonical))
	if members, ok := families[c]; ok {
		out := make([]string, len(members))
		copy(out, members)
		return out
	}
	return []string{c}
}

// FamilyOf returns the canonical protocol name for a given service name. The
// lookup is case-insensitive. If the service does not belong to any known family
// it returns the (lowercased) service name itself.
func FamilyOf(service string) string {
	s := strings.ToLower(strings.TrimSpace(service))
	if canonical, ok := memberToCanonical[s]; ok {
		return canonical
	}
	return s
}

// Families returns a copy of the full canonical -> members map, for listing /
// discovery (e.g. the meow_schema MCP tool). The returned map and slices are
// copies and safe for the caller to mutate.
func Families() map[string][]string {
	out := make(map[string][]string, len(families))
	for canonical, members := range families {
		cp := make([]string, len(members))
		copy(cp, members)
		out[canonical] = cp
	}
	return out
}
