package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

// searchDomains lists domains grouped from service_enrichments with pagination and filters.
func (api *API) searchDomains(c *gin.Context) {
	query := c.DefaultQuery("q", "")
	protocol := c.DefaultQuery("protocol", "")
	statusCode := c.DefaultQuery("status_code", "")

	limitInt, offset, page := parsePagination(c, 50)

	whereClause := "WHERE se.domain != '' AND se.status = 'enriched'"
	args := []any{}

	if query != "" {
		whereClause += " AND LOWER(se.domain) LIKE ?"
		args = append(args, "%"+strings.ToLower(query)+"%")
	}

	if protocol != "" {
		whereClause += " AND se.protocol = ?"
		args = append(args, protocol)
	}

	if statusCode != "" {
		whereClause += " AND se.status_code = ?"
		args = append(args, statusCode)
	}

	// Count total for pagination
	countSQL := fmt.Sprintf(`SELECT COUNT(DISTINCT se.domain) FROM service_enrichments se %s`, whereClause)
	var total int
	if err := api.db.QueryRow(countSQL, args...).Scan(&total); err != nil {
		log.Warn().Err(err).Msg("Failed to count domains")
		total = 0
	}

	querySQL := fmt.Sprintf(`
		SELECT se.domain, COUNT(*) as services_count,
			GROUP_CONCAT(DISTINCT se.protocol) as protocols,
			MAX(se.title) as sample_title,
			MAX(se.status_code) as sample_status_code,
			MAX(se.server) as sample_server,
			MAX(se.enriched_at) as last_seen
		FROM service_enrichments se
		%s
		GROUP BY se.domain
		ORDER BY services_count DESC
		LIMIT ? OFFSET ?`, whereClause)

	args = append(args, limitInt, offset)

	rows, err := api.db.Query(querySQL, args...)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var domains []gin.H
	for rows.Next() {
		var domain string
		var servicesCount int
		var protocols sql.NullString
		var sampleTitle, sampleServer sql.NullString
		var sampleStatusCode sql.NullInt64
		var lastSeen sql.NullInt64

		err := rows.Scan(&domain, &servicesCount, &protocols,
			&sampleTitle, &sampleStatusCode, &sampleServer, &lastSeen)
		if err != nil {
			continue
		}

		d := gin.H{
			"domain":         domain,
			"services_count": servicesCount,
		}
		setIfValid(d, "protocols", protocols)
		setIfValid(d, "sample_title", sampleTitle)
		setIfValid(d, "sample_server", sampleServer)
		setIfValidInt(d, "sample_status_code", sampleStatusCode)
		setIfValidInt(d, "last_seen", lastSeen)

		domains = append(domains, d)
	}
	if err := rows.Err(); err != nil {
		log.Warn().Err(err).Msg("Error iterating domains rows")
	}

	totalPages := max((total+limitInt-1)/limitInt, 1)

	c.JSON(200, gin.H{
		"domains":     domains,
		"total":       total,
		"page":        page,
		"total_pages": totalPages,
	})
}

// getDomainStats returns aggregate domain statistics for stat cards.
func (api *API) getDomainStats(c *gin.Context) {
	var totalDomains, httpDomains, totalEndpoints, uniqueIPs int

	err := api.db.QueryRow(`
		SELECT
			COUNT(DISTINCT domain) as total_domains,
			COUNT(DISTINCT CASE WHEN protocol IN ('http','https') THEN domain END) as http_domains,
			COUNT(DISTINCT ip || ':' || port) as total_endpoints,
			COUNT(DISTINCT ip) as unique_ips
		FROM service_enrichments
		WHERE domain != '' AND status = 'enriched'
	`).Scan(&totalDomains, &httpDomains, &totalEndpoints, &uniqueIPs)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{
		"total_domains":   totalDomains,
		"http_domains":    httpDomains,
		"total_endpoints": totalEndpoints,
		"unique_ips":      uniqueIPs,
	})
}

// getDomainServices returns the services detail for a specific domain with pagination.
func (api *API) getDomainServices(c *gin.Context) {
	domain := c.Param("domain")
	limitInt, offset, page := parsePagination(c, 25)
	hideEmpty := c.DefaultQuery("hide_empty", "") == "1"

	whereClause := "WHERE se.domain = ? AND se.status = 'enriched'"
	if hideEmpty {
		whereClause += " AND se.protocol IN ('http','https') AND COALESCE(se.content_length, 0) > 0"
	}

	// Count total
	var total int
	countSQL := fmt.Sprintf(`SELECT COUNT(*) FROM service_enrichments se %s`, whereClause)
	if err := api.db.QueryRow(countSQL, domain).Scan(&total); err != nil {
		total = 0
	}

	querySQL := fmt.Sprintf(`
		SELECT se.ip, se.port, se.protocol, se.version, se.banner,
			se.status_code, se.title, se.server, se.redirect_url, se.content_length, se.enriched_at,
			h.country_code, h.as_org, h.cloud_provider
		FROM service_enrichments se
		LEFT JOIN hosts h ON se.ip = h.ip
		%s
		ORDER BY se.ip, se.port
		LIMIT ? OFFSET ?`, whereClause)

	rows, err := api.db.Query(querySQL, domain, limitInt, offset)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var services []gin.H
	for rows.Next() {
		var ip string
		var port int
		var protocol, version, banner, title, server, redirectURL sql.NullString
		var countryCode, asOrg, cloudProvider sql.NullString
		var statusCode, contentLength sql.NullInt64
		var enrichedAt sql.NullInt64

		err := rows.Scan(&ip, &port, &protocol, &version, &banner,
			&statusCode, &title, &server, &redirectURL, &contentLength, &enrichedAt,
			&countryCode, &asOrg, &cloudProvider)
		if err != nil {
			continue
		}

		svc := gin.H{
			"ip":   ip,
			"port": port,
		}
		setIfValid(svc, "protocol", protocol)
		setIfValid(svc, "version", version)
		setIfValid(svc, "banner", banner)
		setIfValid(svc, "title", title)
		setIfValid(svc, "server", server)
		setIfValid(svc, "redirect_url", redirectURL)
		setIfValidInt(svc, "status_code", statusCode)
		setIfValidInt(svc, "content_length", contentLength)
		setIfValidInt(svc, "enriched_at", enrichedAt)
		setIfValid(svc, "country_code", countryCode)
		setIfValid(svc, "as_org", asOrg)
		setIfValid(svc, "cloud_provider", cloudProvider)

		services = append(services, svc)
	}
	if err := rows.Err(); err != nil {
		log.Warn().Err(err).Msg("Error iterating domain services rows")
	}

	totalPages := max((total+limitInt-1)/limitInt, 1)

	c.JSON(200, gin.H{
		"services":    services,
		"count":       len(services),
		"total":       total,
		"page":        page,
		"total_pages": totalPages,
		"domain":      domain,
	})
}

// getPreviewBody returns a sanitized HTML body for safe iframe rendering.
// Shared endpoint used by both Domains and Hosts pages.
// Params: ip (required), port (required), domain (optional).
func (api *API) getPreviewBody(c *gin.Context) {
	ip := c.Query("ip")
	portStr := c.Query("port")
	domain := c.Query("domain")

	if ip == "" || portStr == "" {
		c.String(http.StatusBadRequest, "Missing ip or port parameter")
		return
	}

	var rawBody sql.NullString
	var err error
	if domain != "" {
		err = api.db.QueryRow(`
			SELECT json_extract(enrichment_data, '$.body')
			FROM service_enrichments
			WHERE ip = ? AND port = ? AND domain = ?
		`, ip, portStr, domain).Scan(&rawBody)
	} else {
		err = api.db.QueryRow(`
			SELECT json_extract(enrichment_data, '$.body')
			FROM service_enrichments
			WHERE ip = ? AND port = ? AND enrichment_data IS NOT NULL
			LIMIT 1
		`, ip, portStr).Scan(&rawBody)
	}
	if err == sql.ErrNoRows || !rawBody.Valid || rawBody.String == "" {
		c.String(http.StatusNotFound, "No body available")
		return
	}
	if err != nil {
		c.String(http.StatusInternalServerError, "Database error")
		return
	}

	sanitized := sanitizeHTMLBody(rawBody.String)

	c.Header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src data:;")
	c.Header("Referrer-Policy", "no-referrer")
	c.Header("X-Content-Type-Options", "nosniff")
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(sanitized))
}
