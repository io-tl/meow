package main

import (
	"database/sql"
	"encoding/csv"
	"fmt"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/rs/zerolog/log"
	"meow/datastore/pkg/meowql"
)

// parseLimit parses a limit string and returns a safe int value. The requested
// value is honored as-is (no hard cap); only invalid or non-positive input falls
// back to defaultLimit.
func parseLimit(s string, defaultLimit int) int {
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return defaultLimit
	}
	return n
}

// parseExportPage parses the page query parameter (1-based), defaulting to 1.
func parseExportPage(c *gin.Context) int {
	if p, err := strconv.Atoi(c.DefaultQuery("page", "1")); err == nil && p > 0 {
		return p
	}
	return 1
}

// buildExportFilters builds WHERE clause fragments from export query parameters.
// hostWhere: conditions for the hosts table (alias h), with EXISTS subqueries for service-level filters.
// svcWhere: direct conditions for the services table (alias s), used in service-centric exports.
//
// The q parameter supports MeowQL syntax (e.g. "service:ssh", "port:443 country:FR").
// If MeowQL parsing fails, it falls back to free-text LIKE search.
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

	if q != "" {
		// Try MeowQL first
		hostResult := meowql.Compile(q)
		svcResult := meowql.CompileServiceCentric(q)

		if hostResult.Err == nil && hostResult.Where != "" && hostResult.Where != "1=1" {
			hostWhere += " AND " + hostResult.Where
			hostArgs = append(hostArgs, hostResult.Args...)
			if svcResult.Err == nil && svcResult.Where != "" && svcResult.Where != "1=1" {
				svcWhere += " AND " + svcResult.Where
				svcArgs = append(svcArgs, svcResult.Args...)
			}
		} else {
			// Fall back to free-text search
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
	}

	if country != "" {
		hostWhere += " AND h.country_code = ?"
		hostArgs = append(hostArgs, normalizeCountryCode(country))
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
				svcWhere += ` AND (
					LOWER(s.product) LIKE ? OR LOWER(s.service) LIKE ? OR
					EXISTS (SELECT 1 FROM http_data ehd WHERE ehd.ip = s.ip AND ehd.port = s.port AND LOWER(ehd.technologies) LIKE ?)
				)`
				svcArgs = append(svcArgs, techPattern, techPattern, techPattern)
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
			svcWhere += ` AND (
				LOWER(s.product) LIKE ? OR LOWER(s.service) LIKE ? OR
				EXISTS (SELECT 1 FROM http_data ehd WHERE ehd.ip = s.ip AND ehd.port = s.port AND LOWER(ehd.technologies) LIKE ?)
			)`
			svcArgs = append(svcArgs, techPattern, techPattern, techPattern)
		}
	}

	return
}

// exportableTypes lists the data types supported by the export endpoint.
var exportableTypes = map[string]bool{
	"hosts":        true,
	"services":     true,
	"certificates": true,
	"domains":      true,
}

// exportData exports data in various formats (json, csv, txt) and types
// (hosts, services, certificates, domains). The type is validated for every
// format, including txt.
func (api *API) exportData(c *gin.Context) {
	format := c.DefaultQuery("format", "json")
	dataType := c.DefaultQuery("type", "hosts")
	limitStr := c.DefaultQuery("limit", "1000")

	if format != "json" && format != "csv" && format != "txt" {
		c.JSON(400, gin.H{"error": "Unsupported format. Use 'json', 'csv', or 'txt'"})
		return
	}
	if !exportableTypes[dataType] {
		c.JSON(400, gin.H{"error": "Invalid type. Use 'hosts', 'services', 'certificates', or 'domains'"})
		return
	}

	limitInt := parseLimit(limitStr, 1000)
	offset := (parseExportPage(c) - 1) * limitInt

	// TXT format: type-aware plain-text list, streamed one entry per line.
	if format == "txt" {
		api.exportTxt(c, dataType, limitInt, offset)
		return
	}

	var data []gin.H
	var err error
	switch dataType {
	case "hosts":
		data, err = api.exportHosts(c, limitInt, offset)
	case "services":
		data, err = api.exportServices(c, limitInt, offset)
	case "certificates":
		data, err = api.exportCertificates(c, limitInt, offset)
	case "domains":
		data, err = api.exportDomains(c, limitInt, offset)
	}

	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	if data == nil {
		data = []gin.H{}
	}

	switch format {
	case "json":
		c.JSON(200, gin.H{"data": data, "count": len(data)})
	case "csv":
		api.writeCSV(c, dataType, data)
	}
}

// exportTxt streams a plain-text list, one entry per line, scoped to the data type:
//
//	hosts        -> ip
//	services     -> ip:port
//	certificates -> fingerprint_sha256
//	domains      -> domain
//
// Rows are written directly to the response writer (streamed), not buffered.
func (api *API) exportTxt(c *gin.Context, dataType string, limit, offset int) {
	hostWhere, hostArgs, svcWhere, svcArgs := api.buildExportFilters(c)

	var query string
	var args []any
	switch dataType {
	case "hosts":
		query = fmt.Sprintf(`
			SELECT h.ip FROM hosts h
			WHERE %s
			ORDER BY h.last_scan DESC
			LIMIT ? OFFSET ?`, hostWhere)
		args = append(append([]any{}, hostArgs...), limit, offset)
	case "services":
		query = fmt.Sprintf(`
			SELECT s.ip, s.port FROM services s
			INNER JOIN hosts h ON s.ip = h.ip
			WHERE %s AND %s
			ORDER BY s.detected_at DESC
			LIMIT ? OFFSET ?`, hostWhere, svcWhere)
		args = append(append(append([]any{}, hostArgs...), svcArgs...), limit, offset)
	case "certificates":
		certWhere, certArgs := api.certExportWhere(c)
		query = fmt.Sprintf(`
			SELECT c.fingerprint_sha256 FROM certificates c
			WHERE %s
			ORDER BY c.last_seen DESC
			LIMIT ? OFFSET ?`, certWhere)
		args = append(append([]any{}, certArgs...), limit, offset)
	case "domains":
		query = fmt.Sprintf(`
			SELECT hd.domain FROM host_domains hd
			INNER JOIN hosts h ON h.ip = hd.ip
			WHERE %s
			GROUP BY hd.domain
			ORDER BY hd.domain ASC
			LIMIT ? OFFSET ?`, hostWhere)
		args = append(append([]any{}, hostArgs...), limit, offset)
	}

	rows, err := api.db.Query(query, args...)
	if err != nil {
		c.String(500, "Error: %s", err.Error())
		return
	}
	defer rows.Close()

	c.Header("Content-Type", "text/plain; charset=utf-8")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s.txt", dataType))
	c.Status(200)
	w := c.Writer

	for rows.Next() {
		if dataType == "services" {
			var ip string
			var port int
			if err := rows.Scan(&ip, &port); err != nil {
				continue
			}
			fmt.Fprintf(w, "%s:%d\n", ip, port)
			continue
		}
		var val sql.NullString
		if err := rows.Scan(&val); err != nil {
			continue
		}
		if val.Valid && val.String != "" {
			fmt.Fprintf(w, "%s\n", val.String)
		}
	}
}

// writeCSV writes data as a CSV response using encoding/csv, which handles
// header rows and field quoting/escaping (commas, quotes, newlines) per RFC 4180.
// Rows are flushed to the response writer as they are written.
func (api *API) writeCSV(c *gin.Context, dataType string, data []gin.H) {
	c.Header("Content-Type", "text/csv; charset=utf-8")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s.csv", dataType))
	c.Status(200)

	w := csv.NewWriter(c.Writer)
	defer w.Flush()

	switch dataType {
	case "hosts":
		_ = w.Write([]string{"ip", "country_code", "city", "asn", "as_org", "cloud_provider", "cloud_type", "ports"})
		for _, h := range data {
			var ports []string
			if svcs, ok := h["services"].([]gin.H); ok {
				for _, svc := range svcs {
					ports = append(ports, csvStr(svc["port"]))
				}
			}
			_ = w.Write([]string{
				csvStr(h["ip"]), csvStr(h["country_code"]), csvStr(h["city"]),
				csvStr(h["asn"]), csvStr(h["as_org"]),
				csvStr(h["cloud_provider"]), csvStr(h["cloud_type"]),
				strings.Join(ports, " "),
			})
		}
	case "services":
		_ = w.Write([]string{"ip", "port", "service", "product", "version", "banner", "country_code", "cloud_provider"})
		for _, s := range data {
			_ = w.Write([]string{
				csvStr(s["ip"]), csvStr(s["port"]), csvStr(s["service"]),
				csvStr(s["product"]), csvStr(s["version"]), csvStr(s["banner"]),
				csvStr(s["country_code"]), csvStr(s["cloud_provider"]),
			})
		}
	case "certificates":
		_ = w.Write([]string{"fingerprint_sha256", "subject_cn", "subject_org", "issuer_cn", "issuer_org", "names", "not_before", "not_after", "serial_number", "is_self_signed", "is_ca", "host_count"})
		for _, cert := range data {
			_ = w.Write([]string{
				csvStr(cert["fingerprint_sha256"]), csvStr(cert["subject_cn"]), csvStr(cert["subject_org"]),
				csvStr(cert["issuer_cn"]), csvStr(cert["issuer_org"]), csvStr(cert["names"]),
				csvStr(cert["not_before"]), csvStr(cert["not_after"]), csvStr(cert["serial_number"]),
				csvStr(cert["is_self_signed"]), csvStr(cert["is_ca"]), csvStr(cert["host_count"]),
			})
		}
	case "domains":
		_ = w.Write([]string{"domain", "ips", "source", "ip_count"})
		for _, d := range data {
			_ = w.Write([]string{
				csvStr(d["domain"]), csvStr(d["ips"]), csvStr(d["source"]), csvStr(d["ip_count"]),
			})
		}
	}
}

// csvStr converts an arbitrary cell value to its CSV string form. Slices are
// space-joined; nil becomes empty. Quoting/escaping is handled by encoding/csv.
func csvStr(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case []string:
		return strings.Join(x, " ")
	case bool:
		if x {
			return "true"
		}
		return "false"
	default:
		return fmt.Sprintf("%v", x)
	}
}

func (api *API) exportHosts(c *gin.Context, limit, offset int) ([]gin.H, error) {
	hostWhere, hostArgs, svcWhere, svcArgs := api.buildExportFilters(c)

	query := fmt.Sprintf(`
		SELECT h.ip, h.country_code, h.city, h.asn, h.as_org, h.cloud_provider, h.cloud_type
		FROM hosts h
		WHERE %s
		ORDER BY h.last_scan DESC
		LIMIT ? OFFSET ?`, hostWhere)

	rows, err := api.db.Query(query, append(append([]any{}, hostArgs...), limit, offset)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var hosts []gin.H
	var ips []string
	hostIdx := make(map[string]int) // ip -> index in hosts slice

	for rows.Next() {
		var ip sql.NullString
		var countryCode, city, asOrg, cloudProvider, cloudType sql.NullString
		var asn sql.NullInt64

		if err := rows.Scan(&ip, &countryCode, &city, &asn, &asOrg, &cloudProvider, &cloudType); err != nil {
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
		host["services"] = []gin.H{}

		if ip.Valid {
			hostIdx[ip.String] = len(hosts)
			ips = append(ips, ip.String)
		}
		hosts = append(hosts, host)
	}
	if err := rows.Err(); err != nil {
		return hosts, err
	}

	if len(ips) == 0 {
		return hosts, nil
	}

	// Fetch matching services for these hosts
	placeholders := make([]string, len(ips))
	var svcQueryArgs []any
	for i, ip := range ips {
		placeholders[i] = "?"
		svcQueryArgs = append(svcQueryArgs, ip)
	}
	svcQueryArgs = append(svcQueryArgs, svcArgs...)

	// Join hosts so a host-level svcWhere (e.g. from a MeowQL query like
	// "country:GB", compiled service-centric to reference alias h) resolves.
	// Without the join the query errors and every host loses its ports.
	svcQuery := fmt.Sprintf(`
		SELECT s.ip, s.port, s.service, s.product, s.version
		FROM services s
		INNER JOIN hosts h ON h.ip = s.ip
		WHERE s.ip IN (%s) AND %s
		ORDER BY s.port ASC`, strings.Join(placeholders, ","), svcWhere)

	svcRows, err := api.db.Query(svcQuery, svcQueryArgs...)
	if err != nil {
		log.Warn().Err(err).Msg("exportHosts: services sub-fetch failed; hosts returned without ports")
		return hosts, nil
	}
	defer svcRows.Close()

	for svcRows.Next() {
		var ip string
		var port int
		var service, product, version sql.NullString

		if err := svcRows.Scan(&ip, &port, &service, &product, &version); err != nil {
			continue
		}

		if idx, ok := hostIdx[ip]; ok {
			svc := gin.H{"port": port}
			setIfValid(svc, "service", service)
			setIfValid(svc, "product", product)
			setIfValid(svc, "version", version)
			hosts[idx]["services"] = append(hosts[idx]["services"].([]gin.H), svc)
		}
	}

	return hosts, nil
}

func (api *API) exportServices(c *gin.Context, limit, offset int) ([]gin.H, error) {
	hostWhere, hostArgs, svcWhere, svcArgs := api.buildExportFilters(c)

	query := fmt.Sprintf(`
		SELECT s.ip, s.port, s.service, s.product, s.version, s.banner,
		       h.country_code, h.cloud_provider
		FROM services s
		INNER JOIN hosts h ON s.ip = h.ip
		WHERE %s AND %s
		ORDER BY s.detected_at DESC
		LIMIT ? OFFSET ?`, hostWhere, svcWhere)

	args := append(append([]any{}, hostArgs...), svcArgs...)
	args = append(args, limit, offset)

	rows, err := api.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var services []gin.H
	for rows.Next() {
		var ip string
		var port int
		var service, product, version, banner, countryCode, cloudProvider sql.NullString

		if err := rows.Scan(&ip, &port, &service, &product, &version, &banner, &countryCode, &cloudProvider); err != nil {
			continue
		}

		svc := gin.H{"ip": ip, "port": port}
		setIfValid(svc, "service", service)
		setIfValid(svc, "product", product)
		setIfValid(svc, "version", version)
		setIfValid(svc, "banner", banner)
		setIfValid(svc, "country_code", countryCode)
		setIfValid(svc, "cloud_provider", cloudProvider)

		services = append(services, svc)
	}
	if err := rows.Err(); err != nil {
		return services, err
	}

	return services, nil
}

// certExportWhere returns a WHERE fragment (and args) scoping certificates to
// hosts matching the export filters. When no host-level filter is present it
// returns "1=1" (all certificates). The fragment references the certificate
// alias `c`.
func (api *API) certExportWhere(c *gin.Context) (string, []any) {
	hostWhere, hostArgs, _, _ := api.buildExportFilters(c)
	if hostWhere == "1=1" {
		return "1=1", nil
	}
	where := `EXISTS (
		SELECT 1 FROM service_certificates sc
		INNER JOIN hosts h ON h.ip = sc.ip
		WHERE sc.cert_fingerprint = c.fingerprint_sha256 AND ` + hostWhere + `)`
	return where, hostArgs
}

func (api *API) exportCertificates(c *gin.Context, limit, offset int) ([]gin.H, error) {
	certWhere, certArgs := api.certExportWhere(c)

	query := fmt.Sprintf(`
		SELECT c.fingerprint_sha256, c.subject_cn, c.subject_org,
		       c.issuer_cn, c.issuer_org, c.names,
		       c.not_before, c.not_after, c.serial_number,
		       c.is_self_signed, c.is_ca,
		       c.public_key_bits, c.public_key_algorithm, c.signature_algorithm,
		       c.host_count
		FROM certificates c
		WHERE %s
		ORDER BY c.host_count DESC, c.not_after DESC
		LIMIT ? OFFSET ?`, certWhere)

	args := append(append([]any{}, certArgs...), limit, offset)

	rows, err := api.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var certs []gin.H
	for rows.Next() {
		var (
			fingerprint                       string
			subjectCN, subjectOrg             sql.NullString
			issuerCN, issuerOrg, names        sql.NullString
			serialNumber, pubKeyAlgo, sigAlgo sql.NullString
			notBefore, notAfter, pubKeyBits   sql.NullInt64
			isSelfSigned, isCA, hostCount     int
		)

		if err := rows.Scan(
			&fingerprint, &subjectCN, &subjectOrg,
			&issuerCN, &issuerOrg, &names,
			&notBefore, &notAfter, &serialNumber,
			&isSelfSigned, &isCA,
			&pubKeyBits, &pubKeyAlgo, &sigAlgo,
			&hostCount,
		); err != nil {
			continue
		}

		cert := gin.H{
			"fingerprint_sha256": fingerprint,
			"is_self_signed":     isSelfSigned == 1,
			"is_ca":              isCA == 1,
			"host_count":         hostCount,
		}
		setIfValid(cert, "subject_cn", subjectCN)
		setIfValid(cert, "subject_org", subjectOrg)
		setIfValid(cert, "issuer_cn", issuerCN)
		setIfValid(cert, "issuer_org", issuerOrg)
		setIfValid(cert, "names", names)
		setIfValid(cert, "serial_number", serialNumber)
		setIfValid(cert, "public_key_algorithm", pubKeyAlgo)
		setIfValid(cert, "signature_algorithm", sigAlgo)
		setIfValidInt(cert, "public_key_bits", pubKeyBits)
		setIfValidInt(cert, "not_before", notBefore)
		setIfValidInt(cert, "not_after", notAfter)

		certs = append(certs, cert)
	}
	if err := rows.Err(); err != nil {
		return certs, err
	}

	return certs, nil
}

// exportDomains exports domains discovered per host (host_domains table), scoped
// by the export filters at the host level. Each row aggregates the distinct IPs
// and discovery sources for a domain.
func (api *API) exportDomains(c *gin.Context, limit, offset int) ([]gin.H, error) {
	hostWhere, hostArgs, _, _ := api.buildExportFilters(c)

	query := fmt.Sprintf(`
		SELECT hd.domain,
		       GROUP_CONCAT(DISTINCT hd.ip) AS ips,
		       GROUP_CONCAT(DISTINCT hd.source) AS sources,
		       COUNT(DISTINCT hd.ip) AS ip_count
		FROM host_domains hd
		INNER JOIN hosts h ON h.ip = hd.ip
		WHERE %s
		GROUP BY hd.domain
		ORDER BY ip_count DESC, hd.domain ASC
		LIMIT ? OFFSET ?`, hostWhere)

	args := append(append([]any{}, hostArgs...), limit, offset)

	rows, err := api.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var domains []gin.H
	for rows.Next() {
		var domain string
		var ips, sources sql.NullString
		var ipCount int

		if err := rows.Scan(&domain, &ips, &sources, &ipCount); err != nil {
			continue
		}

		d := gin.H{"domain": domain, "ip_count": ipCount}
		if ips.Valid && ips.String != "" {
			d["ips"] = strings.Split(ips.String, ",")
		}
		setIfValid(d, "source", sources)

		domains = append(domains, d)
	}
	if err := rows.Err(); err != nil {
		return domains, err
	}

	return domains, nil
}

// getDebugStats returns debug statistics including NATS and database info
func (api *API) getDebugStats(c *gin.Context) {
	stats := gin.H{}

	// NATS stats
	if api.nc != nil {
		natsStats := gin.H{
			"connected":   api.nc.IsConnected(),
			"url":         api.nc.ConnectedUrl(),
			"servers":     api.nc.Servers(),
			"discovered":  api.nc.DiscoveredServers(),
			"max_payload": api.nc.MaxPayload(),
			"status":      api.nc.Status().String(),
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
						"cid":           conn.Cid,
						"name":          conn.Name,
						"ip":            conn.IP,
						"port":          conn.Port,
						"uptime":        conn.Uptime,
						"in_msgs":       conn.InMsgs,
						"out_msgs":      conn.OutMsgs,
						"in_bytes":      conn.InBytes,
						"out_bytes":     conn.OutBytes,
						"pending":       conn.Pending,
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
		where += " AND h.country_code = ?"
		args = append(args, normalizeCountryCode(country))
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
	}
	if err := rows.Err(); err != nil {
		log.Warn().Err(err).Msg("Error iterating geomap rows")
	}

	// Get true global unique ASN count
	countASNSQL := fmt.Sprintf(`SELECT COUNT(DISTINCT h.asn) FROM hosts h WHERE %s AND h.asn IS NOT NULL`, where)
	if err := api.db.QueryRowLogged(countASNSQL, args...).Scan(&totalASNs); err != nil {
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
	where += " AND h.country_code = ?"
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
	if err := api.db.QueryRowLogged(summarySQL, summaryArgs...).Scan(&name, &hostCount, &totalPorts, &uniqueASNs, &cloudCount); err != nil {
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
