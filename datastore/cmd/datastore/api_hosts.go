package main

import (
	"database/sql"
	"fmt"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

// searchHosts searches hosts with filters and pagination
func (api *API) searchHosts(c *gin.Context) {
	query := c.DefaultQuery("q", "")
	country := c.DefaultQuery("country", "")
	cloud := c.DefaultQuery("cloud", "")
	port := c.DefaultQuery("port", "")
	asn := c.DefaultQuery("asn", "")
	service := c.DefaultQuery("service", "")
	technology := c.DefaultQuery("technology", "")
	verified := c.DefaultQuery("verified", "")

	limitInt, offset, pageInt := parsePagination(c, 50)

	whereClause := "WHERE 1=1"
	args := []any{}

	if query != "" {
		// Normalize query for case-insensitive search
		queryLower := strings.ToLower(strings.TrimSpace(query))
		likeQuery := "%" + queryLower + "%"

		// Check if query looks like an IP address (partial or full)
		if strings.Count(query, ".") >= 1 || isNumeric(query) {
			// IP search - use exact prefix match for better performance
			whereClause += " AND h.ip LIKE ?"
			args = append(args, query+"%")
		} else {
			// Text search - search across multiple fields (case-insensitive)
			whereClause += ` AND (
				LOWER(h.hostnames) LIKE ? OR
				LOWER(h.domains) LIKE ? OR
				LOWER(h.as_org) LIKE ? OR
				LOWER(h.country_name) LIKE ? OR
				LOWER(h.city) LIKE ? OR
				EXISTS (SELECT 1 FROM http_data hd WHERE hd.ip = h.ip AND LOWER(hd.headers) LIKE ?) OR
				EXISTS (SELECT 1 FROM services s WHERE s.ip = h.ip AND (LOWER(s.product) LIKE ? OR LOWER(s.banner) LIKE ?)) OR
				EXISTS (SELECT 1 FROM service_enrichments se WHERE se.ip = h.ip AND (LOWER(se.banner) LIKE ? OR LOWER(se.version) LIKE ?))
			)`
			args = append(args, likeQuery, likeQuery, likeQuery, likeQuery, likeQuery, likeQuery, likeQuery, likeQuery, likeQuery, likeQuery)
		}
	}

	if country != "" {
		whereClause += " AND h.country_code = ?"
		args = append(args, normalizeCountryCode(country))
	}

	if cloud != "" {
		whereClause += " AND LOWER(h.cloud_provider) = LOWER(?)"
		args = append(args, cloud)
	}

	if asn != "" {
		asnClean := strings.TrimPrefix(strings.TrimPrefix(asn, "AS"), "as")
		asnInt, err := strconv.Atoi(asnClean)
		if err == nil {
			whereClause += " AND h.asn = ?"
			args = append(args, asnInt)
		}
	}

	identifiedClause := "(s.service IS NOT NULL OR s.fingerprint_data IS NOT NULL OR s.banner IS NOT NULL OR s.product IS NOT NULL)"

	// verified=true must constrain the same service row as port/service/technology filters.
	if verified == "true" && (port != "" || service != "" || technology != "") {
		portInt, err := strconv.Atoi(port)
		if port == "" || err == nil {
			subWhere := "s.ip = h.ip"
			subArgs := []any{}

			if port != "" {
				subWhere += " AND s.port = ?"
				subArgs = append(subArgs, portInt)
			}

			if service != "" {
				subWhere += " AND LOWER(s.service) = LOWER(?)"
				subArgs = append(subArgs, service)
			}

			if technology != "" {
				techPattern := "%" + strings.ToLower(technology) + "%"
				subWhere += ` AND (
					LOWER(s.product) LIKE ? OR LOWER(s.service) LIKE ? OR
					EXISTS (SELECT 1 FROM http_data hd WHERE hd.ip = s.ip AND hd.port = s.port AND LOWER(hd.technologies) LIKE ?)
				)`
				subArgs = append(subArgs, techPattern, techPattern, techPattern)
			}

			subWhere += " AND " + identifiedClause
			whereClause += " AND EXISTS (SELECT 1 FROM services s WHERE " + subWhere + ")"
			args = append(args, subArgs...)
		}
	} else {
		// Filter hosts that have at least one identified service (not ghost/unverified only)
		if verified == "true" {
			whereClause += " AND EXISTS (SELECT 1 FROM services s WHERE s.ip = h.ip AND " + identifiedClause + ")"
		}

		if port != "" {
			portInt, err := strconv.Atoi(port)
			if err == nil {
				whereClause += " AND EXISTS (SELECT 1 FROM services s WHERE s.ip = h.ip AND s.port = ?)"
				args = append(args, portInt)
			}
		}

		if service != "" {
			whereClause += " AND EXISTS (SELECT 1 FROM services s WHERE s.ip = h.ip AND LOWER(s.service) = LOWER(?))"
			args = append(args, service)
		}

		if technology != "" {
			techPattern := "%" + strings.ToLower(technology) + "%"
			whereClause += ` AND (
				EXISTS (SELECT 1 FROM http_data hd WHERE hd.ip = h.ip AND LOWER(hd.technologies) LIKE ?) OR
				EXISTS (SELECT 1 FROM services s WHERE s.ip = h.ip AND (LOWER(s.product) LIKE ? OR LOWER(s.service) LIKE ?))
			)`
			args = append(args, techPattern, techPattern, techPattern)
		}
	}

	// Count query first (lightweight, no sorting)
	countSQL := fmt.Sprintf("SELECT COUNT(*) FROM hosts h %s", whereClause)
	var total int
	if err := api.db.QueryRowLogged(countSQL, args...).Scan(&total); err != nil {
		log.Error().Err(err).Msg("searchHosts count failed")
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	// Data query with LIMIT (no COUNT(*) OVER() avoids full materialization)
	querySQL := fmt.Sprintf(`
		SELECT h.ip, h.country_code, h.country_name, h.city, h.asn, h.as_org,
		       h.cloud_provider, h.cloud_region, h.cloud_type, h.first_seen, h.last_scan,
		       h.open_ports_count, h.services_count
		FROM hosts h %s
		ORDER BY h.last_scan DESC
		LIMIT ? OFFSET ?`, whereClause)

	args = append(args, limitInt, offset)

	rows, err := api.db.Query(querySQL, args...)
	if err != nil {
		log.Error().Err(err).Str("query", querySQL).Msg("searchHosts query failed")
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var hosts []gin.H
	for rows.Next() {
		var ip string
		var countryCode, countryName, city, cloudProvider, cloudRegion, cloudType, asOrg sql.NullString
		var asnVal, firstSeen, lastScan, openPortsCount, servicesCount sql.NullInt64

		err := rows.Scan(&ip, &countryCode, &countryName, &city, &asnVal, &asOrg,
			&cloudProvider, &cloudRegion, &cloudType, &firstSeen, &lastScan, &openPortsCount, &servicesCount)
		if err != nil {
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
		log.Warn().Err(err).Msg("Error iterating hosts rows")
	}

	// Fetch services for all hosts in batch (for port tags)
	if len(hosts) > 0 {
		ips := make([]any, len(hosts))
		for i, h := range hosts {
			ips[i] = h["ip"]
		}
		placeholders := strings.Repeat("?,", len(ips))
		placeholders = placeholders[:len(placeholders)-1]

		svcQuery := fmt.Sprintf(`
			SELECT ip, port, service, product,
			       CASE WHEN banner IS NOT NULL AND banner != '' THEN 1 ELSE 0 END,
			       CASE WHEN fingerprint_data IS NOT NULL AND fingerprint_data != '' THEN 1 ELSE 0 END
			FROM services WHERE ip IN (%s) ORDER BY ip, port`, placeholders)

		svcRows, err := api.db.Query(svcQuery, ips...)
		if err == nil {
			defer svcRows.Close()
			servicesByIP := make(map[string][]gin.H)
			for svcRows.Next() {
				var svcIP string
				var port, hasBanner, hasFP int
				var svcName, product sql.NullString
				if err := svcRows.Scan(&svcIP, &port, &svcName, &product, &hasBanner, &hasFP); err != nil {
					continue
				}
				svc := gin.H{"port": port}
				setIfValid(svc, "service", svcName)
				setIfValid(svc, "product", product)
				if hasBanner == 1 {
					svc["banner"] = true
				}
				if hasFP == 1 {
					svc["fingerprint_data"] = true
				}
				servicesByIP[svcIP] = append(servicesByIP[svcIP], svc)
			}
			if err := svcRows.Err(); err != nil {
				log.Warn().Err(err).Msg("Error iterating service rows for host batch")
			}
			for i := range hosts {
				if svcs, ok := servicesByIP[hosts[i]["ip"].(string)]; ok {
					hosts[i]["services"] = svcs
				}
			}
		}
	}

	c.JSON(200, gin.H{
		"hosts": hosts,
		"total": total,
		"page":  pageInt,
		"limit": limitInt,
	})
}

// isNumeric checks if a string contains only digits
func isNumeric(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) > 0
}

// getHostDetails gets detailed information about a specific host
func (api *API) getHostDetails(c *gin.Context) {
	ip := c.Param("ip")

	// Get host info
	host, err := api.queryHostInfo(ip)
	if err != nil {
		c.JSON(404, gin.H{"error": "Host not found"})
		return
	}

	// Get services with http_data
	host["services"] = api.queryHostServices(ip)

	// Get certificates
	host["certificates"] = api.queryHostCertificates(ip)

	// Get domains
	host["domains"] = api.queryHostDomains(ip)

	// Get SNI enrichments and attach to services
	enrichmentsByPort := api.queryHostEnrichments(ip)
	if services, ok := host["services"].([]gin.H); ok {
		for i, svc := range services {
			if port, ok := svc["port"].(int); ok {
				if enrichments, exists := enrichmentsByPort[port]; exists && len(enrichments) > 0 {
					services[i]["enrichments"] = enrichments
				}
			}
		}
	}

	c.JSON(200, host)
}

// queryHostInfo returns the host base info or error if not found
func (api *API) queryHostInfo(ip string) (gin.H, error) {
	query := `
		SELECT ip, country_code, country_name, city, asn, as_org, cloud_provider,
		       cloud_region, cloud_type, first_seen, last_scan, open_ports_count, services_count
		FROM hosts WHERE ip = ?`

	var countryCode, countryName, city, cloudProvider, cloudRegion, cloudType, asOrg sql.NullString
	var asn, firstSeen, lastScan, openPortsCount, servicesCount sql.NullInt64

	err := api.db.QueryRowLogged(query, ip).Scan(&ip, &countryCode, &countryName, &city,
		&asn, &asOrg, &cloudProvider, &cloudRegion, &cloudType, &firstSeen, &lastScan, &openPortsCount, &servicesCount)
	if err != nil {
		return nil, err
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
	setIfValidInt(host, "asn", asn)
	setIfValidInt(host, "open_ports_count", openPortsCount)
	setIfValidInt(host, "services_count", servicesCount)

	return host, nil
}

// queryHostServices returns services for a host
func (api *API) queryHostServices(ip string) []gin.H {
	servicesQuery := `
		SELECT s.port, s.service, s.product, s.version, s.banner, s.detected_at, s.enrichment_status,
		       s.enrichment_data, s.fingerprint_data,
		       h.technologies, h.cms, h.framework, h.webserver
		FROM services s
		LEFT JOIN http_data h ON s.ip = h.ip AND s.port = h.port
		WHERE s.ip = ?
		ORDER BY s.port`

	rows, err := api.db.Query(servicesQuery, ip)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var services []gin.H
	for rows.Next() {
		var port int
		var service, product, version, banner, enrichmentStatus sql.NullString
		var enrichmentData, fingerprintData sql.NullString
		var technologies, cms, framework, webserver sql.NullString
		var detectedAt int64

		if err := rows.Scan(&port, &service, &product, &version, &banner,
			&detectedAt, &enrichmentStatus, &enrichmentData, &fingerprintData,
			&technologies, &cms, &framework, &webserver); err != nil {
			continue
		}

		svc := gin.H{
			"port":        port,
			"detected_at": detectedAt,
		}
		setIfValid(svc, "service", service)
		setIfValid(svc, "product", product)
		setIfValid(svc, "version", version)
		setIfValid(svc, "banner", banner)
		setIfValid(svc, "enrichment_status", enrichmentStatus)
		setIfValid(svc, "enrichment_data", enrichmentData)
		setIfValid(svc, "fingerprint_data", fingerprintData)
		setIfValid(svc, "technologies", technologies)
		setIfValid(svc, "cms", cms)
		setIfValid(svc, "framework", framework)
		setIfValid(svc, "webserver", webserver)

		services = append(services, svc)
	}
	if err := rows.Err(); err != nil {
		log.Warn().Err(err).Msg("Error iterating host services rows")
	}
	return services
}

// queryHostCertificates returns certificates for a host
func (api *API) queryHostCertificates(ip string) []gin.H {
	certsQuery := `
		SELECT c.fingerprint_sha256, c.subject_cn, c.issuer_cn, c.not_after
		FROM certificates c
		JOIN service_certificates sc ON c.fingerprint_sha256 = sc.cert_fingerprint
		WHERE sc.ip = ?`

	rows, err := api.db.Query(certsQuery, ip)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var certificates []gin.H
	for rows.Next() {
		var fingerprint, subjectCN, issuerCN sql.NullString
		var notAfter sql.NullInt64

		if err := rows.Scan(&fingerprint, &subjectCN, &issuerCN, &notAfter); err != nil {
			continue
		}

		cert := gin.H{
			"fingerprint_sha256": fingerprint.String,
		}
		setIfValid(cert, "subject_cn", subjectCN)
		setIfValid(cert, "issuer_cn", issuerCN)
		setIfValidInt(cert, "not_after", notAfter)

		certificates = append(certificates, cert)
	}
	if err := rows.Err(); err != nil {
		log.Warn().Err(err).Msg("Error iterating host certificates rows")
	}
	return certificates
}

// queryHostDomains returns domains associated with a host
func (api *API) queryHostDomains(ip string) []gin.H {
	domainsQuery := `
		SELECT domain, source, discovered_port, first_seen, last_seen
		FROM host_domains
		WHERE ip = ?
		ORDER BY last_seen DESC`

	rows, err := api.db.Query(domainsQuery, ip)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var domains []gin.H
	for rows.Next() {
		var domain, source sql.NullString
		var discoveredPort sql.NullInt64
		var firstSeen, lastSeen int64

		if err := rows.Scan(&domain, &source, &discoveredPort, &firstSeen, &lastSeen); err != nil {
			continue
		}

		d := gin.H{
			"domain":     domain.String,
			"source":     source.String,
			"first_seen": firstSeen,
			"last_seen":  lastSeen,
		}
		setIfValidInt(d, "discovered_port", discoveredPort)

		domains = append(domains, d)
	}
	if err := rows.Err(); err != nil {
		log.Warn().Err(err).Msg("Error iterating host domains rows")
	}
	return domains
}

// queryHostEnrichments returns enrichments grouped by port for a host
func (api *API) queryHostEnrichments(ip string) map[int][]gin.H {
	enrichmentsQuery := `
		SELECT port, domain, enrichment_data, status_code, title, server, redirect_url,
		       protocol, version, banner, status, enriched_at
		FROM service_enrichments
		WHERE ip = ?
		ORDER BY port, domain`

	rows, err := api.db.Query(enrichmentsQuery, ip)
	if err != nil {
		return nil
	}
	defer rows.Close()

	enrichmentsByPort := make(map[int][]gin.H)
	for rows.Next() {
		var port int
		var domain, enrichmentData, title, server, redirectURL sql.NullString
		var protocolVal, versionVal, bannerVal, status sql.NullString
		var statusCode, enrichedAt sql.NullInt64

		if err := rows.Scan(&port, &domain, &enrichmentData, &statusCode, &title, &server, &redirectURL,
			&protocolVal, &versionVal, &bannerVal, &status, &enrichedAt); err != nil {
			continue
		}

		e := gin.H{
			"status": status.String,
		}

		if domain.Valid && domain.String != "" {
			e["domain"] = domain.String
		} else {
			e["domain"] = nil // IP Direct
		}
		setIfValid(e, "enrichment_data", enrichmentData)
		setIfValidInt(e, "status_code", statusCode)
		setIfValid(e, "title", title)
		setIfValid(e, "server", server)
		setIfValid(e, "redirect_url", redirectURL)
		setIfValid(e, "protocol", protocolVal)
		setIfValid(e, "version", versionVal)
		setIfValid(e, "banner", bannerVal)
		setIfValidInt(e, "enriched_at", enrichedAt)

		enrichmentsByPort[port] = append(enrichmentsByPort[port], e)
	}
	if err := rows.Err(); err != nil {
		log.Warn().Err(err).Msg("Error iterating host enrichments rows")
	}

	return enrichmentsByPort
}
