package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

// searchDomains lists domains grouped from service_enrichments with pagination and filters.
func (api *API) searchDomains(c *gin.Context) {
	query := c.DefaultQuery("q", "")
	protocol := c.DefaultQuery("protocol", "")
	statusCode := c.DefaultQuery("status_code", "")

	limitInt, offset, page := parsePagination(c, 50)
	cacheKey := fmt.Sprintf("searchDomains:v1:q=%s|protocol=%s|status=%s|page=%d|limit=%d", query, protocol, statusCode, page, limitInt)
	if api.writeCachedJSON(c, cacheKey) {
		return
	}

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
	if err := api.db.QueryRowLogged(countSQL, args...).Scan(&total); err != nil {
		log.Warn().Err(err).Msg("Failed to count domains")
		total = 0
	}

	querySQL := fmt.Sprintf(`
		SELECT se.domain, COUNT(*) as services_count
		FROM service_enrichments se
		%s
		GROUP BY se.domain
		ORDER BY services_count DESC
		LIMIT ? OFFSET ?`, whereClause)

	rows, err := api.db.Query(querySQL, append(args, limitInt, offset)...)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	type domainSummary struct {
		Domain        string
		ServicesCount int
		Protocols     map[string]struct{}
		IPs           []string
		SeenIPs       map[string]struct{}
		IPCount       int
		SampleTitle   string
		SampleServer  string
		SampleStatus  int64
		LastSeen      int64
	}

	var orderedDomains []string
	summaries := make(map[string]*domainSummary)
	for rows.Next() {
		var domain string
		var servicesCount int
		err := rows.Scan(&domain, &servicesCount)
		if err != nil {
			continue
		}
		orderedDomains = append(orderedDomains, domain)
		summaries[domain] = &domainSummary{
			Domain:        domain,
			ServicesCount: servicesCount,
			Protocols:     make(map[string]struct{}),
			SeenIPs:       make(map[string]struct{}),
		}
	}
	if err := rows.Err(); err != nil {
		log.Warn().Err(err).Msg("Error iterating domains rows")
	}

	domains := make([]gin.H, 0, len(orderedDomains))
	if len(orderedDomains) > 0 {
		placeholders := strings.TrimRight(strings.Repeat("?,", len(orderedDomains)), ",")
		detailArgs := make([]any, 0, len(orderedDomains)+2)
		detailArgs = append(detailArgs, "enriched")
		for _, domain := range orderedDomains {
			detailArgs = append(detailArgs, domain)
		}

		detailWhere := fmt.Sprintf("se.status = ? AND se.domain IN (%s)", placeholders)
		if protocol != "" {
			detailWhere += " AND se.protocol = ?"
			detailArgs = append(detailArgs, protocol)
		}
		if statusCode != "" {
			detailWhere += " AND se.status_code = ?"
			detailArgs = append(detailArgs, statusCode)
		}

		detailRows, err := api.db.Query(fmt.Sprintf(`
			SELECT se.domain,
				GROUP_CONCAT(DISTINCT se.protocol) as protocols,
				COUNT(DISTINCT se.ip) as ip_count,
				MAX(se.title) as sample_title,
				MAX(se.status_code) as sample_status_code,
				MAX(se.server) as sample_server,
				MAX(se.enriched_at) as last_seen
			FROM service_enrichments se
			WHERE %s
			GROUP BY se.domain`, detailWhere), detailArgs...)
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		defer detailRows.Close()

		for detailRows.Next() {
			var domain string
			var protocols, title, server sql.NullString
			var ipCount, statusCodeVal, enrichedAt sql.NullInt64
			if err := detailRows.Scan(&domain, &protocols, &ipCount, &title, &statusCodeVal, &server, &enrichedAt); err != nil {
				continue
			}
			summary := summaries[domain]
			if summary == nil {
				continue
			}
			if protocols.Valid && protocols.String != "" {
				for _, p := range strings.Split(protocols.String, ",") {
					p = strings.TrimSpace(p)
					if p != "" {
						summary.Protocols[p] = struct{}{}
					}
				}
			}
			if ipCount.Valid {
				summary.IPCount = int(ipCount.Int64)
			}
			if title.Valid && title.String != "" && summary.SampleTitle == "" {
				summary.SampleTitle = title.String
			}
			if server.Valid && server.String != "" && summary.SampleServer == "" {
				summary.SampleServer = server.String
			}
			if statusCodeVal.Valid && statusCodeVal.Int64 > summary.SampleStatus {
				summary.SampleStatus = statusCodeVal.Int64
			}
			if enrichedAt.Valid && enrichedAt.Int64 > summary.LastSeen {
				summary.LastSeen = enrichedAt.Int64
			}
		}
		if err := detailRows.Err(); err != nil {
			log.Warn().Err(err).Msg("Error iterating domain detail rows")
		}

		ipRows, err := api.db.Query(fmt.Sprintf(`
			SELECT domain, ip
			FROM (
				SELECT domain, ip,
					ROW_NUMBER() OVER (PARTITION BY domain ORDER BY ip) as rn
				FROM (
					SELECT DISTINCT se.domain, se.ip
					FROM service_enrichments se
					WHERE %s
				)
			)
			WHERE rn <= 3
			ORDER BY domain, ip`, detailWhere), detailArgs...)
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		defer ipRows.Close()

		for ipRows.Next() {
			var domain, ip string
			if err := ipRows.Scan(&domain, &ip); err != nil {
				continue
			}
			summary := summaries[domain]
			if summary == nil || ip == "" {
				continue
			}
			summary.IPs = append(summary.IPs, ip)
		}
		if err := ipRows.Err(); err != nil {
			log.Warn().Err(err).Msg("Error iterating domain IP rows")
		}
	}

	for _, domain := range orderedDomains {
		summary := summaries[domain]
		if summary == nil {
			continue
		}
		d := gin.H{
			"domain":         summary.Domain,
			"services_count": summary.ServicesCount,
		}
		if len(summary.Protocols) > 0 {
			protocols := make([]string, 0, len(summary.Protocols))
			for p := range summary.Protocols {
				protocols = append(protocols, p)
			}
			d["protocols"] = strings.Join(protocols, ",")
		}
		if len(summary.IPs) > 0 {
			d["ips"] = summary.IPs
			d["ip_count"] = summary.IPCount
		}
		if summary.SampleTitle != "" {
			d["sample_title"] = summary.SampleTitle
		}
		if summary.SampleServer != "" {
			d["sample_server"] = summary.SampleServer
		}
		if summary.SampleStatus > 0 {
			d["sample_status_code"] = summary.SampleStatus
		}
		if summary.LastSeen > 0 {
			d["last_seen"] = summary.LastSeen
		}
		domains = append(domains, d)
	}

	totalPages := max((total+limitInt-1)/limitInt, 1)

	payload := gin.H{
		"domains":     domains,
		"total":       total,
		"page":        page,
		"total_pages": totalPages,
	}
	api.cacheAndWriteJSON(c, cacheKey, 20*time.Second, payload)
}

// getDomainStats returns aggregate domain statistics for stat cards.
func (api *API) getDomainStats(c *gin.Context) {
	var totalDomains, httpDomains, totalEndpoints, uniqueIPs int

	err := api.db.QueryRowLogged(`
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
	if err := api.db.QueryRowLogged(countSQL, domain).Scan(&total); err != nil {
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
		err = api.db.QueryRowLogged(`
			SELECT json_extract(enrichment_data, '$.body')
			FROM service_enrichments
			WHERE ip = ? AND port = ? AND domain = ?
		`, ip, portStr, domain).Scan(&rawBody)
	} else {
		err = api.db.QueryRowLogged(`
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
