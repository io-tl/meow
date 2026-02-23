package main

import (
	"database/sql"
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"meow/datastore/pkg/meowql"
)

// searchQuery handles MeowQL-powered search across the entire dataset.
// GET /api/search?q=<meowql>&limit=50&page=1
//
// Examples:
//
//	/api/search?q=port:443 and country:US
//	/api/search?q=http.title:"login" and not cloud:aws
//	/api/search?q=ip:192.168.1.0/24 and service:ssh
//	/api/search?q=(port:80 or port:443) and tls.cert.cn:"*.example.com"
//	/api/search?q=port:{22,80,443} and org:"Google"
func (api *API) searchQuery(c *gin.Context) {
	query := c.DefaultQuery("q", "")
	limitInt, offset, pageInt := parsePagination(c, 50)

	// Compile MeowQL query
	result := meowql.Compile(query)
	if result.Err != nil {
		c.JSON(400, gin.H{
			"error":  result.Err.Error(),
			"query":  query,
			"fields": meowql.FieldNames(),
		})
		return
	}

	// Build the full SQL query
	selectCols := `h.ip, h.country_code, h.country_name, h.city,
		h.asn, h.as_org, h.cloud_provider, h.cloud_region, h.cloud_type,
		h.first_seen, h.last_scan, h.open_ports_count, h.services_count`

	querySQL := fmt.Sprintf(
		"SELECT %s FROM hosts h WHERE %s ORDER BY h.last_scan DESC LIMIT ? OFFSET ?",
		selectCols, result.Where,
	)

	args := append(result.Args, limitInt, offset)

	rows, err := api.db.Query(querySQL, args...)
	if err != nil {
		log.Error().Err(err).
			Str("meowql", query).
			Str("sql_where", result.Where).
			Msg("search query failed")
		c.JSON(500, gin.H{"error": "query execution failed"})
		return
	}
	defer rows.Close()

	hosts := scanHostRows(rows)

	// Count total matches (reuse WHERE clause, no LIMIT/OFFSET)
	countSQL := fmt.Sprintf("SELECT COUNT(*) FROM hosts h WHERE %s", result.Where)
	var total int
	if err := api.db.QueryRow(countSQL, result.Args...).Scan(&total); err != nil {
		log.Warn().Err(err).Msg("failed to get search total count")
		total = len(hosts)
	}

	c.JSON(200, gin.H{
		"hosts": hosts,
		"total": total,
		"page":  pageInt,
		"limit": limitInt,
		"query": query,
	})
}

// searchQueryServices searches services using MeowQL.
// GET /api/search/services?q=<meowql>&limit=50&page=1
//
// Unlike /api/search (host-centric), this returns individual services
// with rich data (banner, HTTP info, enrichment, fingerprint, host geo).
// Uses CompileServiceCentric so that service-table conditions (port, service, etc.)
// filter the returned services directly, not just the parent hosts.
func (api *API) searchQueryServices(c *gin.Context) {
	query := c.DefaultQuery("q", "")
	limitInt, offset, pageInt := parsePagination(c, 50)

	// Parse the AST first to extract matched fields
	expr, parseErr := meowql.Parse(query)
	matchedFields := meowql.ExtractFields(expr)

	result := meowql.CompileServiceCentric(query)
	if result.Err != nil {
		c.JSON(400, gin.H{
			"error":  result.Err.Error(),
			"query":  query,
			"fields": meowql.FieldNames(),
		})
		return
	}
	_ = parseErr // CompileServiceCentric already handles parse errors

	// Service-centric query with rich data for cards.
	// LEFT JOIN http_data is 1:1 on PK (ip,port) → zero perf impact.
	querySQL := fmt.Sprintf(`
		SELECT s.ip, s.port, s.service, s.product, s.version, s.banner,
		       s.detected_at, s.enrichment_status,
		       s.fingerprint_data, s.enrichment_data,
		       h.country_code, h.cloud_provider, h.as_org, h.asn, h.city,
		       hd.status_code, hd.title, hd.server, hd.technologies
		FROM services s
		INNER JOIN hosts h ON s.ip = h.ip
		LEFT JOIN http_data hd ON hd.ip = s.ip AND hd.port = s.port
		WHERE %s AND s.enrichment_status != 'pending'
		ORDER BY s.detected_at DESC
		LIMIT ? OFFSET ?`, result.Where)

	args := append(result.Args, limitInt, offset)

	rows, err := api.db.Query(querySQL, args...)
	if err != nil {
		log.Error().Err(err).Str("meowql", query).Msg("service search failed")
		c.JSON(500, gin.H{"error": "query execution failed"})
		return
	}
	defer rows.Close()

	var services []gin.H
	for rows.Next() {
		var ip string
		var port int
		var detectedAt int64
		var svcName, productVal, version, banner, enrichmentStatus sql.NullString
		var fingerprintData, enrichmentData sql.NullString
		var countryCode, cloudProvider, asOrg, city sql.NullString
		var asnVal sql.NullInt64
		var httpStatus sql.NullInt64
		var httpTitle, httpServer, httpTechnologies sql.NullString

		if err := rows.Scan(&ip, &port, &svcName, &productVal, &version, &banner,
			&detectedAt, &enrichmentStatus,
			&fingerprintData, &enrichmentData,
			&countryCode, &cloudProvider, &asOrg, &asnVal, &city,
			&httpStatus, &httpTitle, &httpServer, &httpTechnologies); err != nil {
			continue
		}

		svc := gin.H{"ip": ip, "port": port, "detected_at": detectedAt}
		setIfValid(svc, "service", svcName)
		setIfValid(svc, "product", productVal)
		setIfValid(svc, "version", version)
		setIfValid(svc, "banner", banner)
		setIfValid(svc, "enrichment_status", enrichmentStatus)
		setIfValid(svc, "fingerprint_data", fingerprintData)
		setIfValid(svc, "enrichment_data", enrichmentData)
		setIfValid(svc, "country_code", countryCode)
		setIfValid(svc, "cloud_provider", cloudProvider)
		setIfValid(svc, "as_org", asOrg)
		setIfValid(svc, "city", city)
		setIfValidInt(svc, "asn", asnVal)
		setIfValidInt(svc, "http_status", httpStatus)
		setIfValid(svc, "http_title", httpTitle)
		setIfValid(svc, "http_server", httpServer)
		setIfValid(svc, "http_technologies", httpTechnologies)

		services = append(services, svc)
	}
	if err := rows.Err(); err != nil {
		log.Warn().Err(err).Msg("Error iterating service search rows")
	}

	// Count total matching services (no need for LEFT JOIN in COUNT)
	countSQL := fmt.Sprintf(`
		SELECT COUNT(*) FROM services s
		INNER JOIN hosts h ON s.ip = h.ip
		WHERE %s AND s.enrichment_status != 'pending'`, result.Where)
	var total int
	if err := api.db.QueryRow(countSQL, result.Args...).Scan(&total); err != nil {
		log.Warn().Err(err).Msg("failed to get service search total count")
		total = len(services)
	}

	c.JSON(200, gin.H{
		"services":       services,
		"total":          total,
		"count":          len(services),
		"page":           pageInt,
		"limit":          limitInt,
		"query":          query,
		"matched_fields": matchedFields,
	})
}

// scanHostRows scans host rows into a slice of gin.H.
func scanHostRows(rows *sql.Rows) []gin.H {
	var hosts []gin.H
	for rows.Next() {
		var ip string
		var countryCode, countryName, city, cloudProvider, cloudRegion, cloudType, asOrg sql.NullString
		var asnVal, firstSeen, lastScan, openPortsCount, servicesCount sql.NullInt64

		if err := rows.Scan(&ip, &countryCode, &countryName, &city, &asnVal, &asOrg,
			&cloudProvider, &cloudRegion, &cloudType, &firstSeen, &lastScan, &openPortsCount, &servicesCount); err != nil {
			continue
		}

		host := gin.H{"ip": ip}
		setIfValid(host, "country_code", countryCode)
		setIfValid(host, "country_name", countryName)
		setIfValid(host, "city", city)
		setIfValid(host, "cloud_provider", cloudProvider)
		setIfValid(host, "cloud_region", cloudRegion)
		setIfValid(host, "cloud_type", cloudType)
		setIfValid(host, "as_org", asOrg)
		setIfValidInt(host, "first_seen", firstSeen)
		setIfValidInt(host, "last_scan", lastScan)
		setIfValidInt(host, "asn", asnVal)
		setIfValidInt(host, "open_ports_count", openPortsCount)
		setIfValidInt(host, "services_count", servicesCount)

		hosts = append(hosts, host)
	}
	if err := rows.Err(); err != nil {
		log.Warn().Err(err).Msg("Error iterating host rows")
	}
	return hosts
}
