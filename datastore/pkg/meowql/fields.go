package meowql

import (
	"strings"
	"unicode"
)

// FieldType describes the data type of a field for operator validation.
type FieldType int

const (
	TypeString  FieldType = iota // text comparison
	TypeInteger                  // numeric comparison
	TypeFloat                    // float comparison
	TypeBoolean                  // true/false
	TypeIP                       // IP address (supports CIDR matching)
	TypeJSON                     // dynamic JSON path (json_extract)
)

// Table constants used by the compiler to generate JOINs/EXISTS.
const (
	TableHosts              = "hosts"
	TableServices           = "services"
	TableHTTPData           = "http_data"
	TableCertificates       = "certificates"
	TableServiceCerts       = "service_certificates"
	TableHostDomains        = "host_domains"
	TableServiceEnrichments = "service_enrichments"
)

// FieldInfo describes how a MeowQL field maps to SQL.
type FieldInfo struct {
	Table      string    // SQL table name
	Column     string    // SQL column name
	DataType   FieldType // data type for operator validation
	CaseInsens bool      // apply LOWER() for comparison
	JSONPath   string    // if set, uses json_extract(Column, JSONPath)
}

// FieldRegistry maps MeowQL field names to their SQL metadata.
// Supports both short names (port) and dotted paths (http.title).
var FieldRegistry = map[string]FieldInfo{
	// === Hosts fields (direct on h.*) ===
	"ip":       {Table: TableHosts, Column: "ip", DataType: TypeIP},
	"hostname": {Table: TableHosts, Column: "hostnames", DataType: TypeString, CaseInsens: true},
	"domain":   {Table: TableHostDomains, Column: "domain", DataType: TypeString, CaseInsens: true},
	"asn":      {Table: TableHosts, Column: "asn", DataType: TypeInteger},
	"org":      {Table: TableHosts, Column: "as_org", DataType: TypeString, CaseInsens: true},
	"as_org":   {Table: TableHosts, Column: "as_org", DataType: TypeString, CaseInsens: true},
	"isp":      {Table: TableHosts, Column: "isp", DataType: TypeString, CaseInsens: true},
	"country":  {Table: TableHosts, Column: "country_code", DataType: TypeString, CaseInsens: true},
	"city":     {Table: TableHosts, Column: "city", DataType: TypeString, CaseInsens: true},
	"cloud":        {Table: TableHosts, Column: "cloud_provider", DataType: TypeString, CaseInsens: true},
	"cloud.type":   {Table: TableHosts, Column: "cloud_type", DataType: TypeString, CaseInsens: true},
	"cloud.region": {Table: TableHosts, Column: "cloud_region", DataType: TypeString, CaseInsens: true},
	"timezone":     {Table: TableHosts, Column: "timezone", DataType: TypeString, CaseInsens: true},

	// === Services fields (EXISTS subquery on services) ===
	"port":        {Table: TableServices, Column: "port", DataType: TypeInteger},
	"service":     {Table: TableServices, Column: "service", DataType: TypeString, CaseInsens: true},
	"product":     {Table: TableServices, Column: "product", DataType: TypeString, CaseInsens: true},
	"version":     {Table: TableServices, Column: "version", DataType: TypeString, CaseInsens: true},
	"banner":      {Table: TableServices, Column: "banner", DataType: TypeString, CaseInsens: true},
	"banner_hash": {Table: TableServices, Column: "banner_hash", DataType: TypeString},

	// === HTTP fields (EXISTS subquery on services + http_data) ===
	"http.title":    {Table: TableHTTPData, Column: "title", DataType: TypeString, CaseInsens: true},
	"http.server":   {Table: TableHTTPData, Column: "server", DataType: TypeString, CaseInsens: true},
	"http.status":   {Table: TableHTTPData, Column: "status_code", DataType: TypeInteger},
	"http.body":     {Table: TableHTTPData, Column: "body_preview", DataType: TypeString, CaseInsens: true},
	"http.headers":  {Table: TableHTTPData, Column: "headers", DataType: TypeString, CaseInsens: true},
	"http.favicon":   {Table: TableHTTPData, Column: "favicon_md5", DataType: TypeString},
	"http.redirect":  {Table: TableHTTPData, Column: "redirects_to", DataType: TypeString, CaseInsens: true},
	"http.webserver": {Table: TableHTTPData, Column: "webserver", DataType: TypeString, CaseInsens: true},
	"http.ssl":       {Table: TableHTTPData, Column: "uses_ssl", DataType: TypeBoolean},
	"http.body_hash": {Table: TableHTTPData, Column: "body_hash", DataType: TypeString},
	"framework":      {Table: TableHTTPData, Column: "framework", DataType: TypeString, CaseInsens: true},
	"tech":           {Table: TableHTTPData, Column: "technologies", DataType: TypeString, CaseInsens: true},

	// === Certificate fields (EXISTS subquery with JOINs) ===
	"tls.cert.cn":      {Table: TableCertificates, Column: "subject_cn", DataType: TypeString, CaseInsens: true},
	"tls.cert.issuer":  {Table: TableCertificates, Column: "issuer_cn", DataType: TypeString, CaseInsens: true},
	"tls.cert.org":     {Table: TableCertificates, Column: "subject_org", DataType: TypeString, CaseInsens: true},
	"tls.cert.names":   {Table: TableCertificates, Column: "names", DataType: TypeString, CaseInsens: true},
	"tls.cert.expired":    {Table: TableCertificates, Column: "not_after", DataType: TypeInteger},
	"tls.cert.not_before": {Table: TableCertificates, Column: "not_before", DataType: TypeInteger},
	"tls.cert.algo":       {Table: TableCertificates, Column: "public_key_algorithm", DataType: TypeString},
	"tls.cert.bits":       {Table: TableCertificates, Column: "public_key_bits", DataType: TypeInteger},
	"tls.cert.issuer_org": {Table: TableCertificates, Column: "issuer_org", DataType: TypeString, CaseInsens: true},
	"tls.cert.serial":     {Table: TableCertificates, Column: "serial_number", DataType: TypeString},
	"tls.cert.sig_algo":   {Table: TableCertificates, Column: "signature_algorithm", DataType: TypeString},
	"tls.cert.is_ca":      {Table: TableCertificates, Column: "is_ca", DataType: TypeBoolean},
	"tls.jarm":            {Table: TableServiceCerts, Column: "jarm", DataType: TypeString},
	"tls.chain_position":  {Table: TableServiceCerts, Column: "chain_position", DataType: TypeInteger},
	"tls.self_signed":     {Table: TableCertificates, Column: "is_self_signed", DataType: TypeBoolean},

	// === Host Domains ===
	"domain.source": {Table: TableHostDomains, Column: "source", DataType: TypeString, CaseInsens: true},

	// === Enrichment status ===
	"enrichment": {Table: TableServices, Column: "enrichment_status", DataType: TypeString},
}

// LookupField finds a FieldInfo by name. First tries the static registry,
// then resolves dynamic JSON path fields (enrichment.*, fingerprint.*, http.headers.*).
func LookupField(name string) (FieldInfo, bool) {
	// 1. Static registry (exact match)
	if info, ok := FieldRegistry[name]; ok {
		return info, ok
	}

	// 2. Dynamic JSON path resolution
	return resolveJSONField(name)
}

// jsonPrefixes defines how dynamic field prefixes map to JSON columns.
// Order matters: longer prefixes first to match most specific.
var jsonPrefixes = []struct {
	prefix string
	table  string
	column string
}{
	// enrichment.* → services.enrichment_data
	{"enrichment.", TableServices, "enrichment_data"},
	// fingerprint.* → services.fingerprint_data
	{"fingerprint.", TableServices, "fingerprint_data"},
	// http.headers.* → http_data.headers (JSON object: {"Server":["nginx"],...})
	{"http.headers.", TableHTTPData, "headers"},
	// http.tech.* → http_data.technologies (JSON array of objects)
	{"http.tech.", TableHTTPData, "technologies"},
}

// resolveJSONField resolves a dynamic field name to a JSON path query.
// Examples:
//
//	enrichment.anonymous_login       → json_extract(enrichment_data, '$.anonymous_login')
//	enrichment.tls.version           → json_extract(enrichment_data, '$.tls.version')
//	fingerprint.jarm                 → json_extract(fingerprint_data, '$.jarm')
//	http.headers.X-Powered-By        → json_extract(headers, '$.X-Powered-By')
//	http.headers.Server              → json_extract(headers, '$.Server')
func resolveJSONField(name string) (FieldInfo, bool) {
	for _, jp := range jsonPrefixes {
		if path, ok := strings.CutPrefix(name, jp.prefix); ok {
			if path == "" {
				return FieldInfo{}, false
			}
			if !isValidJSONPath(path) {
				return FieldInfo{}, false
			}
			return FieldInfo{
				Table:    jp.table,
				Column:   jp.column,
				DataType: TypeJSON,
				JSONPath: "$." + path,
			}, true
		}
	}
	return FieldInfo{}, false
}

// isValidJSONPath validates that a JSON path contains only safe characters.
// Allowed: letters, digits, underscores, dots, hyphens.
// This prevents SQL injection via crafted field names like:
//
//	enrichment.x') OR 1=1 --
func isValidJSONPath(path string) bool {
	for _, r := range path {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' && r != '.' && r != '-' {
			return false
		}
	}
	return true
}

// FieldNames returns all registered field names plus dynamic prefixes for help/autocomplete.
func FieldNames() []string {
	names := make([]string, 0, len(FieldRegistry)+len(jsonPrefixes))
	for name := range FieldRegistry {
		names = append(names, name)
	}
	// Add dynamic prefixes as hints
	for _, jp := range jsonPrefixes {
		names = append(names, jp.prefix+"<key>")
	}
	return names
}
