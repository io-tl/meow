package main

import (
	"database/sql"
	"fmt"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/rs/zerolog/log"
	"meow/datastore/pkg/meowql"
)

// parseLimit parses a limit string and returns a safe int value (default 1000, max 10000)
func parseLimit(s string, defaultLimit, maxLimit int) int {
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return defaultLimit
	}
	if n > maxLimit {
		return maxLimit
	}
	return n
}

// buildExportFilters builds WHERE clause fragments from export query parameters.
// hostWhere: conditions for the hosts table (alias h), with EXISTS subqueries for service-level filters.
// svcWhere: direct conditions for the services table (alias s), used in service-centric exports.
func (api *API) buildExportFilters(c *gin.Context) (hostWhere string, hostArgs []any, svcWhere string, svcArgs []any) {
	q := c.DefaultQuery("q", "")
	country := c.DefaultQuery("country", "")
	port := c.DefaultQuery("port", "")
	service := c.DefaultQuery("service", "")
	asn := c.DefaultQuery("asn", "")
	cloud := c.DefaultQuery("cloud", "")
	technology := c.DefaultQuery("technology", "")

	hostWhere = "1=1"
	svcWhere = "1=1"

	// Free-text search (matches searchHosts behavior)
	if q != "" {
		queryLower := strings.ToLower(strings.TrimSpace(q))
		likeQuery := "%" + queryLower + "%"

		if strings.Count(q, ".") >= 1 || isNumeric(q) {
			hostWhere += " AND h.ip LIKE ?"
			hostArgs = append(hostArgs, q+"%")
		} else {
			hostWhere += ` AND (
				LOWER(h.hostnames) LIKE ? OR
				LOWER(h.domains) LIKE ? OR
				LOWER(h.as_org) LIKE ? OR
				LOWER(h.country_name) LIKE ? OR
				LOWER(h.city) LIKE ? OR
				EXISTS (SELECT 1 FROM http_data ehd WHERE ehd.ip = h.ip AND LOWER(ehd.headers) LIKE ?) OR
				EXISTS (SELECT 1 FROM services es WHERE es.ip = h.ip AND (LOWER(es.product) LIKE ? OR LOWER(es.banner) LIKE ?)) OR
				EXISTS (SELECT 1 FROM service_enrichments ese WHERE ese.ip = h.ip AND (LOWER(ese.banner) LIKE ? OR LOWER(ese.version) LIKE ?))
			)`
			hostArgs = append(hostArgs, likeQuery, likeQuery, likeQuery, likeQuery, likeQuery, likeQuery, likeQuery, likeQuery, likeQuery, likeQuery)
		}
	}

	if country != "" {
		hostWhere += " AND UPPER(h.country_code) = UPPER(?)"
		hostArgs = append(hostArgs, country)
	}

	if cloud != "" {
		hostWhere += " AND LOWER(h.cloud_provider) = LOWER(?)"
		hostArgs = append(hostArgs, cloud)
	}

	if asn != "" {
		asnClean := strings.TrimPrefix(strings.TrimPrefix(asn, "AS"), "as")
		if asnInt, err := strconv.Atoi(asnClean); err == nil {
			hostWhere += " AND h.asn = ?"
			hostArgs = append(hostArgs, asnInt)
		}
	}

	// Port + service/technology combined: scope to same service row
	if port != "" && (service != "" || technology != "") {
		portInt, err := strconv.Atoi(port)
		if err == nil {
			subWhere := "es.ip = h.ip AND es.port = ?"
			subArgs := []any{portInt}
			svcWhere += " AND s.port = ?"
			svcArgs = append(svcArgs, portInt)

			if service != "" {
				subWhere += " AND LOWER(es.service) = LOWER(?)"
				subArgs = append(subArgs, service)
				svcWhere += " AND LOWER(s.service) = LOWER(?)"
				svcArgs = append(svcArgs, service)
			}

			if technology != "" {
				techPattern := "%" + strings.ToLower(technology) + "%"
				subWhere += ` AND (
					LOWER(es.product) LIKE ? OR LOWER(es.service) LIKE ? OR
					EXISTS (SELECT 1 FROM http_data ehd WHERE ehd.ip = es.ip AND ehd.port = es.port AND LOWER(ehd.technologies) LIKE ?)
				)`
				subArgs = append(subArgs, techPattern, techPattern, techPattern)
			}

			hostWhere += " AND EXISTS (SELECT 1 FROM services es WHERE " + subWhere + ")"
			hostArgs = append(hostArgs, subArgs...)
		}
	} else {
		if port != "" {
			portInt, err := strconv.Atoi(port)
			if err == nil {
				hostWhere += " AND EXISTS (SELECT 1 FROM services es WHERE es.ip = h.ip AND es.port = ?)"
				hostArgs = append(hostArgs, portInt)
				svcWhere += " AND s.port = ?"
				svcArgs = append(svcArgs, portInt)
			}
		}

		if service != "" {
			hostWhere += " AND EXISTS (SELECT 1 FROM services es WHERE es.ip = h.ip AND LOWER(es.service) = LOWER(?))"
			hostArgs = append(hostArgs, service)
			svcWhere += " AND LOWER(s.service) = LOWER(?)"
			svcArgs = append(svcArgs, service)
		}

		if technology != "" {
			techPattern := "%" + strings.ToLower(technology) + "%"
			hostWhere += ` AND (
				EXISTS (SELECT 1 FROM http_data ehd WHERE ehd.ip = h.ip AND LOWER(ehd.technologies) LIKE ?) OR
				EXISTS (SELECT 1 FROM services es WHERE es.ip = h.ip AND (LOWER(es.product) LIKE ? OR LOWER(es.service) LIKE ?))
			)`
			hostArgs = append(hostArgs, techPattern, techPattern, techPattern)
		}
	}

	return
}

// exportData exports data in various formats
func (api *API) exportData(c *gin.Context) {
	format := c.DefaultQuery("format", "json")
	dataType := c.DefaultQuery("type", "hosts")
	limitStr := c.DefaultQuery("limit", "1000")

	if format != "json" && format != "csv" && format != "txt" {
		c.JSON(400, gin.H{"error": "Unsupported format. Use 'json', 'csv', or 'txt'"})
		return
	}

	limitInt := parseLimit(limitStr, 1000, 10000)

	// TXT format: always export ip:port from services
	if format == "txt" {
		api.exportServicesTxt(c, limitInt)
		return
	}

	var data []gin.H
	var err error

	switch dataType {
	case "hosts":
		data, err = api.exportHosts(c, limitInt)
	case "services":
		data, err = api.exportServices(c, limitInt)
	case "certificates":
		data, err = api.exportCertificates(limitInt)
	default:
		c.JSON(400, gin.H{"error": "Invalid type. Use 'hosts', 'services', or 'certificates'"})
		return
	}

	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	switch format {
	case "json":
		c.JSON(200, gin.H{"data": data, "count": len(data)})
	case "csv":
		api.writeCSV(c, dataType, data)
	}
}

// exportServicesTxt returns plain text with ip:port per line
func (api *API) exportServicesTxt(c *gin.Context, limit int) {
	hostWhere, hostArgs, svcWhere, svcArgs := api.buildExportFilters(c)

	query := fmt.Sprintf(`
		SELECT s.ip, s.port FROM services s
		INNER JOIN hosts h ON s.ip = h.ip
		WHERE %s AND %s
		ORDER BY s.detected_at DESC
		LIMIT ?`, hostWhere, svcWhere)

	args := append(hostArgs, svcArgs...)
	args = append(args, limit)

	rows, err := api.db.Query(query, args...)
	if err != nil {
		c.String(500, "Error: %s", err.Error())
		return
	}
	defer rows.Close()

	c.Header("Content-Type", "text/plain; charset=utf-8")
	var sb strings.Builder
	for rows.Next() {
		var ip string
		var port int
		if err := rows.Scan(&ip, &port); err != nil {
			continue
		}
		fmt.Fprintf(&sb, "%s:%d\n", ip, port)
	}
	c.String(200, sb.String())
}

// writeCSV writes data as CSV response
func (api *API) writeCSV(c *gin.Context, dataType string, data []gin.H) {
	c.Header("Content-Type", "text/csv; charset=utf-8")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s.csv", dataType))

	var sb strings.Builder

	switch dataType {
	case "hosts":
		sb.WriteString("ip,country_code,city,asn,as_org,cloud_provider,cloud_type,open_ports_count\n")
		for _, h := range data {
			fmt.Fprintf(&sb, "%s,%s,%s,%s,%s,%s,%s,%s\n",
				csvEscape(h["ip"]), csvEscape(h["country_code"]), csvEscape(h["city"]),
				csvEscape(h["asn"]), csvEscape(h["as_org"]),
				csvEscape(h["cloud_provider"]), csvEscape(h["cloud_type"]),
				csvEscape(h["open_ports_count"]))
		}
	case "services":
		sb.WriteString("ip,port,service,product,version\n")
		for _, s := range data {
			fmt.Fprintf(&sb, "%s,%s,%s,%s,%s\n",
				csvEscape(s["ip"]), csvEscape(s["port"]),
				csvEscape(s["service"]), csvEscape(s["product"]), csvEscape(s["version"]))
		}
	case "certificates":
		sb.WriteString("fingerprint,subject_cn,issuer_cn,not_after\n")
		for _, cert := range data {
			fmt.Fprintf(&sb, "%s,%s,%s,%s\n",
				csvEscape(cert["fingerprint"]), csvEscape(cert["subject_cn"]),
				csvEscape(cert["issuer_cn"]), csvEscape(cert["not_after"]))
		}
	}

	c.String(200, sb.String())
}

// csvEscape formats a value for CSV output, quoting if necessary
func csvEscape(v any) string {
	if v == nil {
		return ""
	}
	s := fmt.Sprintf("%v", v)
	if strings.ContainsAny(s, ",\"\n\r") {
		return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
	}
	return s
}

func (api *API) exportHosts(c *gin.Context, limit int) ([]gin.H, error) {
	hostWhere, hostArgs, _, _ := api.buildExportFilters(c)

	query := fmt.Sprintf(`
		SELECT h.ip, h.country_code, h.city, h.asn, h.as_org, h.cloud_provider, h.cloud_type, h.open_ports_count
		FROM hosts h
		WHERE %s
		ORDER BY h.last_scan DESC
		LIMIT ?`, hostWhere)

	hostArgs = append(hostArgs, limit)

	rows, err := api.db.Query(query, hostArgs...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var hosts []gin.H
	for rows.Next() {
		var ip sql.NullString
		var countryCode, city, asOrg, cloudProvider, cloudType sql.NullString
		var asn, openPortsCount sql.NullInt64

		if err := rows.Scan(&ip, &countryCode, &city, &asn, &asOrg, &cloudProvider, &cloudType, &openPortsCount); err != nil {
			continue
		}

		host := gin.H{}
		setIfValid(host, "ip", ip)
		setIfValid(host, "country_code", countryCode)
		setIfValid(host, "city", city)
		setIfValidInt(host, "asn", asn)
		setIfValid(host, "as_org", asOrg)
		setIfValid(host, "cloud_provider", cloudProvider)
		setIfValid(host, "cloud_type", cloudType)
		setIfValidInt(host, "open_ports_count", openPortsCount)

		hosts = append(hosts, host)
	}
	if err := rows.Err(); err != nil {
		return hosts, err
	}

	return hosts, nil
}

func (api *API) exportServices(c *gin.Context, limit int) ([]gin.H, error) {
	hostWhere, hostArgs, svcWhere, svcArgs := api.buildExportFilters(c)

	query := fmt.Sprintf(`
		SELECT s.ip, s.port, s.service, s.product, s.version
		FROM services s
		INNER JOIN hosts h ON s.ip = h.ip
		WHERE %s AND %s
		ORDER BY s.detected_at DESC
		LIMIT ?`, hostWhere, svcWhere)

	args := append(hostArgs, svcArgs...)
	args = append(args, limit)

	rows, err := api.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var services []gin.H
	for rows.Next() {
		var ip string
		var port int
		var service, product, version sql.NullString

		if err := rows.Scan(&ip, &port, &service, &product, &version); err != nil {
			continue
		}

		svc := gin.H{"ip": ip, "port": port}
		setIfValid(svc, "service", service)
		setIfValid(svc, "product", product)
		setIfValid(svc, "version", version)

		services = append(services, svc)
	}
	if err := rows.Err(); err != nil {
		return services, err
	}

	return services, nil
}

func (api *API) exportCertificates(limit int) ([]gin.H, error) {
	rows, err := api.db.Query(`
		SELECT fingerprint_sha256, subject_cn, issuer_cn, not_after
		FROM certificates
		ORDER BY last_seen DESC
		LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var certs []gin.H
	for rows.Next() {
		var fingerprint string
		var subjectCN, issuerCN sql.NullString
		var notAfter sql.NullInt64

		if err := rows.Scan(&fingerprint, &subjectCN, &issuerCN, &notAfter); err != nil {
			continue
		}

		cert := gin.H{"fingerprint": fingerprint}
		setIfValid(cert, "subject_cn", subjectCN)
		setIfValid(cert, "issuer_cn", issuerCN)
		setIfValidInt(cert, "not_after", notAfter)

		certs = append(certs, cert)
	}
	if err := rows.Err(); err != nil {
		return certs, err
	}

	return certs, nil
}

// getDebugStats returns debug statistics including NATS and database info
func (api *API) getDebugStats(c *gin.Context) {
	stats := gin.H{}

	// NATS stats
	if api.nc != nil {
		natsStats := gin.H{
			"connected":     api.nc.IsConnected(),
			"url":           api.nc.ConnectedUrl(),
			"servers":       api.nc.Servers(),
			"discovered":    api.nc.DiscoveredServers(),
			"max_payload":   api.nc.MaxPayload(),
			"status":        api.nc.Status().String(),
		}

		// Get connection stats
		connStats := api.nc.Stats()
		natsStats["in_msgs"] = connStats.InMsgs
		natsStats["out_msgs"] = connStats.OutMsgs
		natsStats["in_bytes"] = connStats.InBytes
		natsStats["out_bytes"] = connStats.OutBytes
		natsStats["reconnects"] = connStats.Reconnects

		// Get connected clients/peers info from embedded server
		if api.ns != nil {
			connzOpts := &natsserver.ConnzOptions{
				Subscriptions: true, // Include subscription details
			}
			connz, err := api.ns.Connz(connzOpts)
			if err == nil {
				clients := []gin.H{}
				for _, conn := range connz.Conns {
					client := gin.H{
						"cid":          conn.Cid,
						"name":         conn.Name,
						"ip":           conn.IP,
						"port":         conn.Port,
						"uptime":       conn.Uptime,
						"in_msgs":      conn.InMsgs,
						"out_msgs":     conn.OutMsgs,
						"in_bytes":     conn.InBytes,
						"out_bytes":    conn.OutBytes,
						"pending":      conn.Pending,
						"subscriptions": conn.NumSubs,
					}

					// Add subscription details
					if len(conn.Subs) > 0 {
						subs := []string{}
						for _, sub := range conn.Subs {
							subs = append(subs, sub)
						}
						client["subjects"] = subs
					}

					clients = append(clients, client)
				}
				natsStats["clients"] = clients
				natsStats["total_connections"] = connz.NumConns
			}
		}

		stats["nats"] = natsStats
	}

	// Database stats
	dbStats := gin.H{}

	// Table counts
	hostsCount, servicesCount, certsCount, _ := api.db.getTableCounts()
	dbStats["hosts"] = hostsCount
	dbStats["services"] = servicesCount
	dbStats["certificates"] = certsCount

	// Services by type
	serviceTypes := []gin.H{}
	rows, err := api.db.Query(`
		SELECT COALESCE(service, 'unknown') as service_type, COUNT(*) as count
		FROM services
		WHERE service IS NOT NULL AND service != ''
		GROUP BY service
		ORDER BY count DESC
		LIMIT 10
	`)
	if err == nil {
		for rows.Next() {
			var serviceType string
			var count int64
			if err := rows.Scan(&serviceType, &count); err == nil {
				serviceTypes = append(serviceTypes, gin.H{
					"type":  serviceType,
					"count": count,
				})
			}
		}
		if err := rows.Err(); err != nil {
			log.Warn().Err(err).Msg("Error iterating debug service type rows")
		}
		rows.Close()
	}
	dbStats["top_services"] = serviceTypes

	// Enrichment status
	enriched, pending, failed, skipped, _ := api.db.getEnrichmentStatusCounts()
	dbStats["enrichment"] = gin.H{
		"enriched": enriched,
		"pending":  pending,
		"failed":   failed,
		"skipped":  skipped,
	}

	stats["database"] = dbStats

	c.JSON(200, stats)
}

// buildGeoMapFilters builds WHERE clause and args from geomap filter parameters.
// Returns the WHERE fragment (without leading "AND") and its args.
func (api *API) buildGeoMapFilters(c *gin.Context) (string, []any) {
	q := c.DefaultQuery("q", "")
	country := c.DefaultQuery("country", "")
	port := c.DefaultQuery("port", "")
	service := c.DefaultQuery("service", "")
	asn := c.DefaultQuery("asn", "")
	cloud := c.DefaultQuery("cloud", "")

	where := "h.country_code IS NOT NULL"
	var args []any

	// MeowQL query
	if q != "" {
		result := meowql.Compile(q)
		if result.Err == nil && result.Where != "" && result.Where != "1=1" {
			where += " AND " + result.Where
			args = append(args, result.Args...)
		}
	}

	// Traditional filters
	if country != "" {
		where += " AND UPPER(h.country_code) = UPPER(?)"
		args = append(args, country)
	}

	if port != "" {
		portInt, err := strconv.Atoi(port)
		if err == nil {
			where += " AND EXISTS (SELECT 1 FROM services s WHERE s.ip = h.ip AND s.port = ?)"
			args = append(args, portInt)
		}
	}

	if service != "" {
		where += " AND EXISTS (SELECT 1 FROM services s WHERE s.ip = h.ip AND LOWER(s.service) = LOWER(?))"
		args = append(args, service)
	}

	if asn != "" {
		asnClean := strings.TrimPrefix(strings.TrimPrefix(asn, "AS"), "as")
		asnInt, err := strconv.Atoi(asnClean)
		if err == nil {
			where += " AND h.asn = ?"
			args = append(args, asnInt)
		}
	}

	if cloud != "" {
		where += " AND LOWER(h.cloud_provider) = LOWER(?)"
		args = append(args, cloud)
	}

	return where, args
}

// getGeoMap returns geographical distribution data for map visualization
// GET /api/geomap?q=<meowql>&port=&service=&asn=&cloud=&country=
// Backward-compatible: also supports ?groups= for legacy callers
func (api *API) getGeoMap(c *gin.Context) {
	// Legacy backward compat: if only groups= is provided (no other filters)
	serviceGroups := c.DefaultQuery("groups", "")
	q := c.DefaultQuery("q", "")
	port := c.DefaultQuery("port", "")
	service := c.DefaultQuery("service", "")
	asn := c.DefaultQuery("asn", "")
	cloud := c.DefaultQuery("cloud", "")
	country := c.DefaultQuery("country", "")

	isLegacy := serviceGroups != "" && q == "" && port == "" && service == "" && asn == "" && cloud == "" && country == ""

	if isLegacy {
		api.getGeoMapLegacy(c, serviceGroups)
		return
	}

	where, args := api.buildGeoMapFilters(c)

	querySQL := fmt.Sprintf(`
		SELECT h.country_code, h.country_name,
		       COUNT(*) as host_count,
		       COALESCE(SUM(h.open_ports_count), 0) as total_ports,
		       COUNT(DISTINCT h.asn) as unique_asns,
		       SUM(CASE WHEN h.cloud_provider IS NOT NULL AND h.cloud_provider != '' THEN 1 ELSE 0 END) as cloud_count
		FROM hosts h
		WHERE %s
		GROUP BY h.country_code, h.country_name
		ORDER BY host_count DESC`, where)

	rows, err := api.db.Query(querySQL, args...)
	if err != nil {
		log.Error().Err(err).Msg("getGeoMap query failed")
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var countries []gin.H
	var totalHosts, totalPorts, totalASNs, totalCloud int

	asnSet := make(map[int]bool)

	for rows.Next() {
		var code, name string
		var hostCount, ports, asns, cloudCount int
		if err := rows.Scan(&code, &name, &hostCount, &ports, &asns, &cloudCount); err != nil {
			continue
		}
		countries = append(countries, gin.H{
			"code":        code,
			"name":        name,
			"host_count":  hostCount,
			"total_ports": ports,
			"unique_asns": asns,
			"cloud_count": cloudCount,
		})
		totalHosts += hostCount
		totalPorts += ports
		totalCloud += cloudCount
		// Approximate unique ASNs across countries (sum of per-country distinct)
		_ = asnSet
	}
	if err := rows.Err(); err != nil {
		log.Warn().Err(err).Msg("Error iterating geomap rows")
	}

	// Get true global unique ASN count
	countASNSQL := fmt.Sprintf(`SELECT COUNT(DISTINCT h.asn) FROM hosts h WHERE %s AND h.asn IS NOT NULL`, where)
	if err := api.db.QueryRow(countASNSQL, args...).Scan(&totalASNs); err != nil {
		// Fallback: sum per-country unique_asns
		for _, c := range countries {
			totalASNs += c["unique_asns"].(int)
		}
	}

	c.JSON(200, gin.H{
		"countries": countries,
		"totals": gin.H{
			"hosts":     totalHosts,
			"countries": len(countries),
			"asns":      totalASNs,
			"ports":     totalPorts,
		},
	})
}

// getGeoMapLegacy handles the old ?groups= parameter for backward compatibility
func (api *API) getGeoMapLegacy(c *gin.Context, serviceGroups string) {
	portGroups := map[string][]int{
		"admin": {22, 23, 3389, 5900, 5901},
		"http":  {80, 443, 8080, 8443, 8000, 8888},
		"mail":  {25, 110, 143, 465, 587, 993, 995},
		"file":  {21, 445, 139, 111, 2049, 548},
		"db":    {3306, 5432, 1433, 1521, 27017, 6379, 5984, 9200},
	}

	requestedGroups := strings.Split(serviceGroups, ",")
	var allPorts []int
	for _, group := range requestedGroups {
		group = strings.TrimSpace(group)
		if ports, ok := portGroups[group]; ok {
			allPorts = append(allPorts, ports...)
		}
	}

	if len(allPorts) == 0 {
		c.JSON(200, gin.H{"countries": []gin.H{}, "totals": gin.H{"hosts": 0, "countries": 0, "asns": 0, "ports": 0}})
		return
	}

	placeholders := make([]string, len(allPorts))
	var args []any
	for i, port := range allPorts {
		placeholders[i] = "?"
		args = append(args, port)
	}

	query := fmt.Sprintf(`
		SELECT h.country_code, h.country_name, COUNT(DISTINCT h.ip) as host_count,
		       COUNT(s.port) as total_ports,
		       COUNT(DISTINCT h.asn) as unique_asns,
		       SUM(CASE WHEN h.cloud_provider IS NOT NULL AND h.cloud_provider != '' THEN 1 ELSE 0 END) as cloud_count
		FROM hosts h
		INNER JOIN services s ON h.ip = s.ip
		WHERE h.country_code IS NOT NULL AND s.port IN (%s)
		GROUP BY h.country_code, h.country_name
		ORDER BY host_count DESC`, strings.Join(placeholders, ","))

	rows, err := api.db.Query(query, args...)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var countries []gin.H
	var totalHosts, totalPorts, totalASNs, totalCloud int
	for rows.Next() {
		var code, name string
		var hostCount, ports, asns, cloudCount int
		if err := rows.Scan(&code, &name, &hostCount, &ports, &asns, &cloudCount); err != nil {
			continue
		}
		countries = append(countries, gin.H{
			"code":        code,
			"name":        name,
			"host_count":  hostCount,
			"total_ports": ports,
			"unique_asns": asns,
			"cloud_count": cloudCount,
		})
		totalHosts += hostCount
		totalPorts += ports
		totalASNs += asns
		totalCloud += cloudCount
	}
	if err := rows.Err(); err != nil {
		log.Warn().Err(err).Msg("Error iterating geomap legacy rows")
	}

	c.JSON(200, gin.H{
		"countries": countries,
		"totals": gin.H{
			"hosts":     totalHosts,
			"countries": len(countries),
			"asns":      totalASNs,
			"ports":     totalPorts,
		},
	})
}

// getGeoMapCountryDetails returns detailed breakdown for a specific country
// GET /api/geomap/country/:code?q=&port=&service=&asn=&cloud=
func (api *API) getGeoMapCountryDetails(c *gin.Context) {
	code := strings.ToUpper(c.Param("code"))
	if code == "" {
		c.JSON(400, gin.H{"error": "country code required"})
		return
	}

	where, args := api.buildGeoMapFilters(c)

	// Force country filter
	where += " AND UPPER(h.country_code) = UPPER(?)"
	args = append(args, code)

	// 1. Summary stats
	summarySQL := fmt.Sprintf(`
		SELECT COALESCE(h.country_name, ?) as name,
		       COUNT(*) as host_count,
		       COALESCE(SUM(h.open_ports_count), 0) as total_ports,
		       COUNT(DISTINCT h.asn) as unique_asns,
		       SUM(CASE WHEN h.cloud_provider IS NOT NULL AND h.cloud_provider != '' THEN 1 ELSE 0 END) as cloud_count
		FROM hosts h
		WHERE %s`, where)

	summaryArgs := append([]any{code}, args...)
	var name string
	var hostCount, totalPorts, uniqueASNs, cloudCount int
	if err := api.db.QueryRow(summarySQL, summaryArgs...).Scan(&name, &hostCount, &totalPorts, &uniqueASNs, &cloudCount); err != nil {
		log.Error().Err(err).Str("country", code).Msg("country details summary failed")
		c.JSON(500, gin.H{"error": "query failed"})
		return
	}

	result := gin.H{
		"code":        code,
		"name":        name,
		"host_count":  hostCount,
		"total_ports": totalPorts,
		"unique_asns": uniqueASNs,
		"cloud_count": cloudCount,
	}

	// 2. Top services
	svcSQL := fmt.Sprintf(`
		SELECT s.service, COUNT(*) as cnt
		FROM services s
		INNER JOIN hosts h ON s.ip = h.ip
		WHERE %s AND s.service IS NOT NULL AND s.service != ''
		GROUP BY s.service
		ORDER BY cnt DESC
		LIMIT 10`, where)
	result["top_services"] = api.queryKVPairs(svcSQL, args)

	// 3. Top ports
	portSQL := fmt.Sprintf(`
		SELECT s.port, COUNT(*) as cnt
		FROM services s
		INNER JOIN hosts h ON s.ip = h.ip
		WHERE %s
		GROUP BY s.port
		ORDER BY cnt DESC
		LIMIT 10`, where)
	result["top_ports"] = api.queryIntKVPairs(portSQL, args)

	// 4. Top ASNs
	asnSQL := fmt.Sprintf(`
		SELECT h.asn, h.as_org, COUNT(*) as cnt
		FROM hosts h
		WHERE %s AND h.asn IS NOT NULL
		GROUP BY h.asn, h.as_org
		ORDER BY cnt DESC
		LIMIT 10`, where)
	result["top_asns"] = api.queryASNPairs(asnSQL, args)

	// 5. Top cloud providers
	cloudSQL := fmt.Sprintf(`
		SELECT h.cloud_provider, COUNT(*) as cnt
		FROM hosts h
		WHERE %s AND h.cloud_provider IS NOT NULL AND h.cloud_provider != ''
		GROUP BY h.cloud_provider
		ORDER BY cnt DESC
		LIMIT 10`, where)
	result["top_cloud_providers"] = api.queryKVPairs(cloudSQL, args)

	// 6. Top cities
	citySQL := fmt.Sprintf(`
		SELECT h.city, COUNT(*) as cnt
		FROM hosts h
		WHERE %s AND h.city IS NOT NULL AND h.city != ''
		GROUP BY h.city
		ORDER BY cnt DESC
		LIMIT 10`, where)
	result["top_cities"] = api.queryKVPairs(citySQL, args)

	c.JSON(200, result)
}

// queryKVPairs executes a query returning (string_key, count) rows
func (api *API) queryKVPairs(query string, args []any) []gin.H {
	rows, err := api.db.Query(query, args...)
	if err != nil {
		log.Warn().Err(err).Msg("queryKVPairs failed")
		return []gin.H{}
	}
	defer rows.Close()

	var results []gin.H
	for rows.Next() {
		var key string
		var count int
		if err := rows.Scan(&key, &count); err != nil {
			continue
		}
		results = append(results, gin.H{"name": key, "count": count})
	}
	if err := rows.Err(); err != nil {
		log.Warn().Err(err).Msg("Error iterating queryKVPairs rows")
	}
	if results == nil {
		return []gin.H{}
	}
	return results
}

// queryIntKVPairs executes a query returning (int_key, count) rows
func (api *API) queryIntKVPairs(query string, args []any) []gin.H {
	rows, err := api.db.Query(query, args...)
	if err != nil {
		log.Warn().Err(err).Msg("queryIntKVPairs failed")
		return []gin.H{}
	}
	defer rows.Close()

	var results []gin.H
	for rows.Next() {
		var key, count int
		if err := rows.Scan(&key, &count); err != nil {
			continue
		}
		results = append(results, gin.H{"port": key, "count": count})
	}
	if err := rows.Err(); err != nil {
		log.Warn().Err(err).Msg("Error iterating queryIntKVPairs rows")
	}
	if results == nil {
		return []gin.H{}
	}
	return results
}

// queryASNPairs executes a query returning (asn, as_org, count) rows
func (api *API) queryASNPairs(query string, args []any) []gin.H {
	rows, err := api.db.Query(query, args...)
	if err != nil {
		log.Warn().Err(err).Msg("queryASNPairs failed")
		return []gin.H{}
	}
	defer rows.Close()

	var results []gin.H
	for rows.Next() {
		var asn, count int
		var asOrg sql.NullString
		if err := rows.Scan(&asn, &asOrg, &count); err != nil {
			continue
		}
		results = append(results, gin.H{"asn": asn, "as_org": nullStr(asOrg), "count": count})
	}
	if err := rows.Err(); err != nil {
		log.Warn().Err(err).Msg("Error iterating queryASNPairs rows")
	}
	if results == nil {
		return []gin.H{}
	}
	return results
}

