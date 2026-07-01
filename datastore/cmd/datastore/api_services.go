package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

// getCertificateDetail returns full details for a single certificate including PEM
func (api *API) getCertificateDetail(c *gin.Context) {
	fingerprint := c.Param("fingerprint")

	var (
		fp, fpSHA1, fpMD5                     sql.NullString
		subjectCN, subjectOrg, subjectCountry sql.NullString
		issuerCN, issuerOrg, names            sql.NullString
		serialNumber, pubKeyAlgo, sigAlgo     sql.NullString
		parsedCert                            sql.NullString
		notBefore, notAfter                   sql.NullInt64
		firstSeen, lastSeen                   sql.NullInt64
		pubKeyBits                            sql.NullInt64
		isSelfSigned, isCA                    int
	)

	err := api.db.QueryRowLogged(`
		SELECT fingerprint_sha256, fingerprint_sha1, fingerprint_md5,
		       subject_cn, subject_org, subject_country,
		       issuer_cn, issuer_org, names,
		       not_before, not_after, serial_number,
		       public_key_bits, public_key_algorithm, signature_algorithm,
		       is_self_signed, is_ca, first_seen, last_seen,
		       parsed_cert
		FROM certificates WHERE fingerprint_sha256 = ?`, fingerprint).Scan(
		&fp, &fpSHA1, &fpMD5,
		&subjectCN, &subjectOrg, &subjectCountry,
		&issuerCN, &issuerOrg, &names,
		&notBefore, &notAfter, &serialNumber,
		&pubKeyBits, &pubKeyAlgo, &sigAlgo,
		&isSelfSigned, &isCA, &firstSeen, &lastSeen,
		&parsedCert,
	)
	if err == sql.ErrNoRows {
		c.JSON(404, gin.H{"error": "certificate not found"})
		return
	}
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	cert := gin.H{
		"is_self_signed": isSelfSigned == 1,
		"is_ca":          isCA == 1,
	}
	setIfValid(cert, "fingerprint_sha256", fp)
	setIfValid(cert, "fingerprint_sha1", fpSHA1)
	setIfValid(cert, "fingerprint_md5", fpMD5)
	setIfValid(cert, "subject_cn", subjectCN)
	setIfValid(cert, "subject_org", subjectOrg)
	setIfValid(cert, "subject_country", subjectCountry)
	setIfValid(cert, "issuer_cn", issuerCN)
	setIfValid(cert, "issuer_org", issuerOrg)
	setIfValid(cert, "names", names)
	setIfValid(cert, "serial_number", serialNumber)
	setIfValid(cert, "public_key_algorithm", pubKeyAlgo)
	setIfValid(cert, "signature_algorithm", sigAlgo)
	setIfValidInt(cert, "public_key_bits", pubKeyBits)
	setIfValidInt(cert, "not_before", notBefore)
	setIfValidInt(cert, "not_after", notAfter)
	setIfValidInt(cert, "first_seen", firstSeen)
	setIfValidInt(cert, "last_seen", lastSeen)

	if parsedCert.Valid {
		var certData map[string]any
		if err := json.Unmarshal([]byte(parsedCert.String), &certData); err == nil {
			if pem, ok := certData["pem"].(string); ok {
				cert["pem"] = pem
			}
		}
	}

	c.JSON(200, cert)
}

// searchServices searches services with filters
func (api *API) searchServices(c *gin.Context) {
	query := c.DefaultQuery("q", "")
	service := c.DefaultQuery("service", "")
	product := c.DefaultQuery("product", "")
	protocol := c.DefaultQuery("protocol", "")

	limitInt, offset, _ := parsePagination(c, 50)

	whereClause := "WHERE 1=1"
	args := []any{}

	needHTTPJoin := false
	if query != "" {
		needHTTPJoin = true
		likeQuery := "%" + query + "%"
		likeQueryLower := "%" + strings.ToLower(query) + "%"
		whereClause += ` AND (
			s.ip LIKE ? OR
			s.banner LIKE ? OR
			LOWER(s.product) LIKE ? OR
			LOWER(s.version) LIKE ? OR
			LOWER(hd.headers) LIKE ? OR
			EXISTS (SELECT 1 FROM service_enrichments se WHERE se.ip = s.ip AND se.port = s.port AND (LOWER(se.banner) LIKE ? OR LOWER(se.version) LIKE ?))
		)`
		args = append(args, likeQuery, likeQuery, likeQueryLower, likeQueryLower, likeQueryLower, likeQueryLower, likeQueryLower)
	}

	if service != "" {
		whereClause += " AND s.service = ?"
		args = append(args, service)
	}

	if product != "" {
		whereClause += " AND s.product LIKE ?"
		args = append(args, "%"+product+"%")
	}

	if protocol != "" {
		whereClause += " AND EXISTS (SELECT 1 FROM service_enrichments se WHERE se.ip = s.ip AND se.port = s.port AND se.protocol = ?)"
		args = append(args, protocol)
	}

	httpJoin := ""
	if needHTTPJoin {
		httpJoin = "LEFT JOIN http_data hd ON s.ip = hd.ip AND s.port = hd.port"
	}

	querySQL := fmt.Sprintf(`
		SELECT s.ip, s.port, s.service, s.product, s.version, s.banner,
		       s.detected_at, s.enrichment_status,
		       h.country_code, h.cloud_provider
		FROM services s
		LEFT JOIN hosts h ON s.ip = h.ip
		%s
		%s
		ORDER BY s.detected_at DESC
		LIMIT ? OFFSET ?`, httpJoin, whereClause)

	args = append(args, limitInt, offset)

	rows, err := api.db.Query(querySQL, args...)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var services []gin.H
	for rows.Next() {
		var ip string
		var port int
		var detectedAt int64
		var svcName, productVal, version, banner, enrichmentStatus, countryCode, cloudProvider sql.NullString

		err := rows.Scan(&ip, &port, &svcName, &productVal, &version, &banner,
			&detectedAt, &enrichmentStatus, &countryCode, &cloudProvider)
		if err != nil {
			continue
		}

		svc := gin.H{
			"ip":          ip,
			"port":        port,
			"detected_at": detectedAt,
		}
		setIfValid(svc, "service", svcName)
		setIfValid(svc, "product", productVal)
		setIfValid(svc, "version", version)
		setIfValid(svc, "banner", banner)
		setIfValid(svc, "enrichment_status", enrichmentStatus)
		setIfValid(svc, "country_code", countryCode)
		setIfValid(svc, "cloud_provider", cloudProvider)

		services = append(services, svc)
	}
	if err := rows.Err(); err != nil {
		log.Warn().Err(err).Msg("Error iterating services rows")
	}

	c.JSON(200, gin.H{"services": services})
}

// searchCertificates searches certificates with filters
func (api *API) searchCertificates(c *gin.Context) {
	query := c.DefaultQuery("q", "")
	subject := c.DefaultQuery("subject", "")
	issuer := c.DefaultQuery("issuer", "")
	status := c.DefaultQuery("status", "")
	algo := c.DefaultQuery("algo", "")

	limitInt, offset, page := parsePagination(c, 50)

	whereClause := "WHERE 1=1"
	args := []any{}

	if query != "" {
		likeQuery := "%" + query + "%"
		whereClause += ` AND (c.subject_cn LIKE ? OR c.names LIKE ? OR c.fingerprint_sha256 LIKE ?
			OR c.serial_number LIKE ? OR c.issuer_cn LIKE ? OR c.issuer_org LIKE ?
			OR c.subject_org LIKE ?)`
		args = append(args, likeQuery, likeQuery, likeQuery, likeQuery, likeQuery, likeQuery, likeQuery)
	}

	if subject != "" {
		whereClause += " AND c.subject_cn LIKE ?"
		args = append(args, "%"+subject+"%")
	}

	if issuer != "" {
		whereClause += " AND (c.issuer_cn LIKE ? OR c.issuer_org LIKE ?)"
		args = append(args, "%"+issuer+"%", "%"+issuer+"%")
	}

	// Status filter — semantics mirror the client's computeStatus so the stat-card
	// quick filters and the dropdown agree with the summary counts.
	now := time.Now().Unix()
	switch status {
	case "expired":
		whereClause += " AND c.not_after IS NOT NULL AND c.not_after < ?"
		args = append(args, now)
	case "valid":
		whereClause += " AND (c.not_after IS NULL OR c.not_after >= ?) AND c.is_self_signed = 0"
		args = append(args, now)
	case "expiring-soon":
		whereClause += " AND c.not_after >= ? AND c.not_after <= ? AND c.is_self_signed = 0"
		args = append(args, now, now+30*86400)
	case "self-signed":
		whereClause += " AND c.is_self_signed = 1"
	case "ca":
		whereClause += " AND c.is_ca = 1"
	}

	if algo != "" {
		whereClause += " AND c.public_key_algorithm LIKE ?"
		args = append(args, "%"+algo+"%")
	}

	var total int
	countSQL := "SELECT COUNT(*) FROM certificates c " + whereClause
	if err := api.db.QueryRowLogged(countSQL, args...).Scan(&total); err != nil {
		total = 0
	}

	// Sort — whitelist maps the client column keys to safe SQL expressions.
	sortExpr := map[string]string{
		"subject_cn":           "c.subject_cn",
		"issuer_cn":            "c.issuer_cn",
		"public_key_algorithm": "c.public_key_algorithm",
		"not_after":            "c.not_after",
		"host_count":           "c.host_count",
		"san_count":            "CASE WHEN json_valid(c.names) THEN json_array_length(c.names) ELSE 0 END",
	}[c.DefaultQuery("sort", "host_count")]
	if sortExpr == "" {
		sortExpr = "c.host_count"
	}
	order := "DESC"
	if strings.EqualFold(c.DefaultQuery("order", "desc"), "asc") {
		order = "ASC"
	}
	// c.fingerprint_sha256 as final tiebreaker keeps pagination deterministic.
	orderBy := fmt.Sprintf("ORDER BY %s %s, c.not_after DESC, c.fingerprint_sha256", sortExpr, order)

	querySQL := fmt.Sprintf(`
		SELECT c.fingerprint_sha256, c.fingerprint_sha1, c.fingerprint_md5,
		       c.subject_cn, c.subject_org, c.subject_country,
		       c.issuer_cn, c.issuer_org, c.names,
		       c.not_before, c.not_after, c.serial_number,
		       c.public_key_bits, c.public_key_algorithm, c.signature_algorithm,
		       c.is_self_signed, c.is_ca, c.first_seen, c.last_seen,
		       c.host_count
		FROM certificates c
		%s
		%s
		LIMIT ? OFFSET ?`, whereClause, orderBy)

	args = append(args, limitInt, offset)

	rows, err := api.db.Query(querySQL, args...)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var certificates []gin.H
	for rows.Next() {
		var (
			fingerprint, fingerprintSHA1, fingerprintMD5 sql.NullString
			subjectCN, subjectOrg, subjectCountry        sql.NullString
			issuerCN, issuerOrg, names                   sql.NullString
			serialNumber, pubKeyAlgo, sigAlgo            sql.NullString
			notBefore, notAfter                          sql.NullInt64
			firstSeen, lastSeen                          sql.NullInt64
			pubKeyBits                                   sql.NullInt64
			isSelfSigned, isCA, hostCount                int
		)

		err := rows.Scan(
			&fingerprint, &fingerprintSHA1, &fingerprintMD5,
			&subjectCN, &subjectOrg, &subjectCountry,
			&issuerCN, &issuerOrg, &names,
			&notBefore, &notAfter, &serialNumber,
			&pubKeyBits, &pubKeyAlgo, &sigAlgo,
			&isSelfSigned, &isCA, &firstSeen, &lastSeen,
			&hostCount,
		)
		if err != nil {
			continue
		}

		cert := gin.H{
			"is_self_signed": isSelfSigned == 1,
			"is_ca":          isCA == 1,
			"host_count":     hostCount,
		}
		setIfValid(cert, "fingerprint_sha256", fingerprint)
		setIfValid(cert, "fingerprint_sha1", fingerprintSHA1)
		setIfValid(cert, "fingerprint_md5", fingerprintMD5)
		setIfValid(cert, "subject_cn", subjectCN)
		setIfValid(cert, "subject_org", subjectOrg)
		setIfValid(cert, "subject_country", subjectCountry)
		setIfValid(cert, "issuer_cn", issuerCN)
		setIfValid(cert, "issuer_org", issuerOrg)
		setIfValid(cert, "names", names)
		setIfValid(cert, "serial_number", serialNumber)
		setIfValid(cert, "public_key_algorithm", pubKeyAlgo)
		setIfValid(cert, "signature_algorithm", sigAlgo)
		setIfValidInt(cert, "public_key_bits", pubKeyBits)
		setIfValidInt(cert, "not_before", notBefore)
		setIfValidInt(cert, "not_after", notAfter)
		setIfValidInt(cert, "first_seen", firstSeen)
		setIfValidInt(cert, "last_seen", lastSeen)

		certificates = append(certificates, cert)
	}
	if err := rows.Err(); err != nil {
		log.Warn().Err(err).Msg("Error iterating certificates rows")
	}

	totalPages := max((total+limitInt-1)/limitInt, 1)
	c.JSON(200, gin.H{
		"certificates": certificates,
		"total":        total,
		"page":         page,
		"total_pages":  totalPages,
	})
}

// getCertificatesSummary returns whole-dataset certificate stats and facets.
// The certificates page uses this for its stat cards and issuer/algorithm chips,
// so the numbers reflect the full database (not just the current page). Counts
// mirror the client's calculateStats semantics.
func (api *API) getCertificatesSummary(c *gin.Context) {
	now := time.Now().Unix()

	var total, valid, expired, selfSigned, ca int
	// COALESCE guards the empty-table case where SUM() returns NULL.
	err := api.db.QueryRowLogged(`
		SELECT
			COUNT(*),
			COALESCE(SUM(CASE WHEN (not_after IS NULL OR not_after >= ?) AND is_self_signed = 0 THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN not_after IS NOT NULL AND not_after < ? THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN is_self_signed = 1 THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN is_ca = 1 THEN 1 ELSE 0 END), 0)
		FROM certificates`, now, now).Scan(&total, &valid, &expired, &selfSigned, &ca)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	topIssuers := api.certFacet(`
		SELECT CASE WHEN issuer_cn IS NULL OR issuer_cn = '' THEN 'Unknown' ELSE issuer_cn END AS name,
		       COUNT(*) AS cnt
		FROM certificates
		GROUP BY name ORDER BY cnt DESC LIMIT 8`)

	// Algorithm facets keep the bits breakdown for display (e.g. "RSA 2048");
	// clicking one filters by the algorithm family via the algo param.
	topAlgos := []gin.H{}
	rows, err := api.db.Query(`
		SELECT public_key_algorithm, public_key_bits, COUNT(*) AS cnt
		FROM certificates
		WHERE public_key_algorithm IS NOT NULL AND public_key_algorithm != ''
		GROUP BY public_key_algorithm, public_key_bits
		ORDER BY cnt DESC LIMIT 6`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var algo sql.NullString
			var bits sql.NullInt64
			var cnt int
			if err := rows.Scan(&algo, &bits, &cnt); err != nil {
				continue
			}
			name := algo.String
			if bits.Valid && bits.Int64 > 0 {
				name = fmt.Sprintf("%s %d", algo.String, bits.Int64)
			}
			topAlgos = append(topAlgos, gin.H{"name": name, "algo": algo.String, "count": cnt})
		}
	}

	c.JSON(200, gin.H{
		"total":          total,
		"valid":          valid,
		"expired":        expired,
		"self_signed":    selfSigned,
		"ca":             ca,
		"top_issuers":    topIssuers,
		"top_algorithms": topAlgos,
	})
}

// certFacet runs a "SELECT name, cnt" grouping query and returns [{name,count}].
func (api *API) certFacet(query string) []gin.H {
	out := []gin.H{}
	rows, err := api.db.Query(query)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var name sql.NullString
		var cnt int
		if err := rows.Scan(&name, &cnt); err != nil {
			continue
		}
		out = append(out, gin.H{"name": nullStr(name), "count": cnt})
	}
	return out
}

// getCertificateHosts gets all hosts using a specific certificate
func (api *API) getCertificateHosts(c *gin.Context) {
	fingerprint := c.Param("fingerprint")

	// First, get the certificate details including PEM
	var parsedCert, names string
	certQuery := `SELECT parsed_cert, names FROM certificates WHERE fingerprint_sha256 = ?`
	err := api.db.QueryRowLogged(certQuery, fingerprint).Scan(&parsedCert, &names)
	if err != nil && err != sql.ErrNoRows {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	// Get hosts using this certificate
	querySQL := `
		SELECT DISTINCT h.ip, h.country_code, h.country_name, h.city,
		       h.asn, h.as_org, sc.port
		FROM service_certificates sc
		JOIN hosts h ON sc.ip = h.ip
		WHERE sc.cert_fingerprint = ?
		ORDER BY h.ip, sc.port
	`

	rows, err := api.db.Query(querySQL, fingerprint)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var hosts []gin.H
	for rows.Next() {
		var ip string
		var countryCode, countryName, city, asOrg sql.NullString
		var asn sql.NullInt64
		var port int

		err := rows.Scan(&ip, &countryCode, &countryName, &city, &asn, &asOrg, &port)
		if err != nil {
			continue
		}

		host := gin.H{
			"ip":   ip,
			"port": port,
		}
		setIfValid(host, "country_code", countryCode)
		setIfValid(host, "country_name", countryName)
		setIfValid(host, "city", city)
		setIfValidInt(host, "asn", asn)
		setIfValid(host, "as_org", asOrg)

		hosts = append(hosts, host)
	}
	if err := rows.Err(); err != nil {
		log.Warn().Err(err).Msg("Error iterating certificate hosts rows")
	}

	c.JSON(200, gin.H{
		"hosts":       hosts,
		"count":       len(hosts),
		"parsed_cert": parsedCert,
		"names":       names,
	})
}
