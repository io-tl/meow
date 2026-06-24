package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

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

	limitInt, _, _ := parsePagination(c, 50)

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

	querySQL := fmt.Sprintf(`
		SELECT c.fingerprint_sha256, c.fingerprint_sha1, c.fingerprint_md5,
		       c.subject_cn, c.subject_org, c.subject_country,
		       c.issuer_cn, c.issuer_org, c.names,
		       c.not_before, c.not_after, c.serial_number,
		       c.public_key_bits, c.public_key_algorithm, c.signature_algorithm,
		       c.is_self_signed, c.is_ca, c.first_seen, c.last_seen,
		       COALESCE(sc_counts.host_count, 0) as host_count
		FROM certificates c
		LEFT JOIN (
		    SELECT cert_fingerprint, COUNT(DISTINCT ip) as host_count
		    FROM service_certificates
		    GROUP BY cert_fingerprint
		) sc_counts ON sc_counts.cert_fingerprint = c.fingerprint_sha256
		%s
		ORDER BY host_count DESC, c.not_after DESC
		LIMIT ?`, whereClause)

	args = append(args, limitInt)

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

	c.JSON(200, gin.H{"certificates": certificates})
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
