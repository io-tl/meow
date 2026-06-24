package main

import (
	"fmt"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"meow/datastore/pkg/meowql"
)

// fieldDescription provides human-readable descriptions for autocomplete.
var fieldDescriptions = map[string]string{
	"ip":                  "IP address (CIDR supported)",
	"hostname":            "Hostname",
	"domain":              "Associated domain",
	"asn":                 "AS number",
	"org":                 "AS organization",
	"as_org":              "AS organization",
	"isp":                 "ISP name",
	"country":             "Country code (US, DE, FR...)",
	"city":                "City name",
	"cloud":               "Cloud provider (aws, gcp, azure)",
	"cloud.type":          "Cloud instance type",
	"cloud.region":        "Cloud region",
	"timezone":            "Timezone (America/New_York...)",
	"port":                "Port number",
	"service":             "Service name (http, ssh, ftp...)",
	"product":             "Product name (nginx, OpenSSH...)",
	"version":             "Product version",
	"banner":              "Raw banner text",
	"banner_hash":         "Banner hash",
	"http.title":          "HTTP page title",
	"http.server":         "HTTP Server header",
	"http.status":         "HTTP status code",
	"http.body":           "HTTP body preview",
	"http.headers":        "HTTP headers",
	"http.favicon":        "Favicon MD5 hash",
	"http.redirect":       "Redirect URL",
	"http.webserver":      "Webserver (nginx, apache...)",
	"http.ssl":            "Uses SSL/TLS (true/false)",
	"http.body_hash":      "SHA256 of HTTP body",
	"framework":           "Framework (Laravel, Django...)",
	"tech":                "Technologies",
	"tls.cert.cn":         "Certificate subject CN",
	"tls.cert.issuer":     "Certificate issuer",
	"tls.cert.org":        "Certificate organization",
	"tls.cert.names":      "Certificate SANs",
	"tls.cert.not_before": "Certificate not before (Unix timestamp)",
	"tls.cert.issuer_org": "Certificate issuer organization",
	"tls.cert.serial":     "Certificate serial number (hex)",
	"tls.cert.sig_algo":   "Certificate signature algorithm",
	"tls.cert.is_ca":      "Certificate is CA (true/false)",
	"tls.jarm":            "JARM TLS fingerprint",
	"tls.chain_position":  "Certificate chain position (0=leaf)",
	"tls.self_signed":     "Self-signed certificate",
	"domain.source":       "Domain discovery source (certificate, sni...)",
	"enrichment":          "Enrichment status",
}

// dynamicPrefixDescriptions for JSON dynamic prefixes.
var dynamicPrefixDescriptions = map[string]string{
	"enrichment.":   "Enrichment data (JSON path)",
	"fingerprint.":  "Fingerprint data (JSON path)",
	"http.headers.": "HTTP header value",
	"http.tech.":    "Technology detail",
}

// valueQueries maps field names to SQL queries that return top values.
// Only indexed, simple fields are supported to avoid table scans.
var valueQueries = map[string]struct {
	query string
}{
	"country":     {query: "SELECT country_code, COUNT(*) as cnt FROM hosts WHERE country_code IS NOT NULL AND country_code != '' GROUP BY country_code ORDER BY cnt DESC LIMIT 10"},
	"service":     {query: "SELECT service, COUNT(*) as cnt FROM services WHERE service IS NOT NULL AND service != '' GROUP BY service ORDER BY cnt DESC LIMIT 10"},
	"product":     {query: "SELECT product, COUNT(*) as cnt FROM services WHERE product IS NOT NULL AND product != '' GROUP BY product ORDER BY cnt DESC LIMIT 10"},
	"cloud":       {query: "SELECT cloud_provider, COUNT(*) as cnt FROM hosts WHERE cloud_provider IS NOT NULL AND cloud_provider != '' GROUP BY cloud_provider ORDER BY cnt DESC LIMIT 10"},
	"org":         {query: "SELECT as_org, COUNT(*) as cnt FROM hosts WHERE as_org IS NOT NULL AND as_org != '' GROUP BY as_org ORDER BY cnt DESC LIMIT 10"},
	"framework":   {query: "SELECT framework, COUNT(*) as cnt FROM http_data WHERE framework IS NOT NULL AND framework != '' GROUP BY framework ORDER BY cnt DESC LIMIT 10"},
	"http.server": {query: "SELECT server, COUNT(*) as cnt FROM http_data WHERE server IS NOT NULL AND server != '' GROUP BY server ORDER BY cnt DESC LIMIT 10"},
	"enrichment":  {query: "SELECT enrichment_status, COUNT(*) as cnt FROM services WHERE enrichment_status IS NOT NULL AND enrichment_status != '' GROUP BY enrichment_status ORDER BY cnt DESC LIMIT 10"},
}

// getAutocomplete returns field or value suggestions.
// GET /api/autocomplete?prefix=<text>&field=<field_name>
func (api *API) getAutocomplete(c *gin.Context) {
	prefix := c.DefaultQuery("prefix", "")
	field := c.DefaultQuery("field", "")

	if field != "" {
		// Mode 2: return top values for this field
		api.autocompleteValues(c, field, prefix)
		return
	}

	// Mode 1: return matching field names
	api.autocompleteFields(c, prefix)
}

func (api *API) autocompleteFields(c *gin.Context, prefix string) {
	prefix = strings.ToLower(prefix)

	type suggestion struct {
		Field       string `json:"field"`
		Description string `json:"description"`
		Type        string `json:"type"` // "field" or "prefix"
	}

	var suggestions []suggestion

	// Static fields from FieldRegistry
	for name := range meowql.FieldRegistry {
		if prefix == "" || strings.HasPrefix(strings.ToLower(name), prefix) {
			desc := fieldDescriptions[name]
			if desc == "" {
				desc = name
			}
			suggestions = append(suggestions, suggestion{
				Field:       name,
				Description: desc,
				Type:        "field",
			})
		}
	}

	// Dynamic JSON prefixes
	for pfx, desc := range dynamicPrefixDescriptions {
		if prefix == "" || strings.HasPrefix(pfx, prefix) || strings.HasPrefix(prefix, pfx) {
			suggestions = append(suggestions, suggestion{
				Field:       pfx,
				Description: desc,
				Type:        "prefix",
			})
		}
	}

	c.JSON(200, gin.H{"suggestions": suggestions})
}

func (api *API) autocompleteValues(c *gin.Context, field, prefix string) {
	vq, ok := valueQueries[field]
	if !ok {
		c.JSON(200, gin.H{"values": []gin.H{}})
		return
	}

	rows, err := api.db.Query(vq.query)
	if err != nil {
		c.JSON(200, gin.H{"values": []gin.H{}})
		return
	}
	defer rows.Close()

	prefix = strings.ToLower(prefix)

	var values []gin.H
	for rows.Next() {
		var val string
		var cnt int
		if err := rows.Scan(&val, &cnt); err != nil {
			continue
		}
		if prefix != "" && !strings.Contains(strings.ToLower(val), prefix) {
			continue
		}
		values = append(values, gin.H{
			"value": val,
			"count": cnt,
		})
	}
	if err := rows.Err(); err != nil {
		log.Warn().Err(err).Str("field", field).Msg("Error iterating autocomplete value rows")
	}

	if values == nil {
		values = []gin.H{}
	}

	c.JSON(200, gin.H{
		"values": values,
		"field":  field,
		"total":  len(values),
		"label":  fmt.Sprintf("Top values for %s", field),
	})
}
