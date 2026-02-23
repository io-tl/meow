package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"strings"

	"github.com/nats-io/nats.go"
	"github.com/rs/zerolog/log"
)

func (c *Consumer) handleFingerprinted(msg *nats.Msg) {
	var event FingerprintEvent
	if err := json.Unmarshal(msg.Data, &event); err != nil {
		log.Error().Err(err).Str("raw_message", string(msg.Data)).Msg("Failed to unmarshal fingerprint event")
		return
	}

	// Skip failed fingerprints — don't overwrite existing data
	// We still receive them so we know the port was attempted
	if event.Failed {
		log.Debug().
			Str("ip", event.IP).
			Int("port", event.Port).
			Str("reason", event.FailReason).
			Msg("Received failed fingerprint event, skipping DB update")
		// Mark as skipped — fingerprint failed, no enrichment will occur
		if _, err := c.db.Exec(`UPDATE services SET enrichment_status = ?
			WHERE ip = ? AND port = ? AND (enrichment_status IS NULL OR enrichment_status = ?)`,
			StatusSkipped, event.IP, event.Port, StatusPending); err != nil {
			log.Warn().Err(err).Str("ip", event.IP).Int("port", event.Port).Msg("Failed to mark service as skipped")
		}
		return
	}

	// Parse timestamp
	detectedAt := int64(event.Timestamp)

	// Early duplicate detection: check if we already have this exact fingerprint
	var existingService, existingProduct, existingVersion, existingBanner sql.NullString
	var existingDetectedAt sql.NullInt64
	err := c.db.QueryRow(`
		SELECT service, product, version, banner, detected_at
		FROM services
		WHERE ip = ? AND port = ?`,
		event.IP, event.Port).Scan(&existingService, &existingProduct, &existingVersion, &existingBanner, &existingDetectedAt)

	if err != nil && err != sql.ErrNoRows {
		log.Error().Err(err).Str("ip", event.IP).Int("port", event.Port).Msg("DB error during fingerprint duplicate check")
		return
	}
	if err == nil {
		// Service exists, check if fingerprint is identical
		// Only skip if we already have valid fingerprint data (service is not null/empty)
		hasExistingFingerprint := existingService.Valid && existingService.String != ""
		serviceMatch := existingService.Valid && existingService.String == event.Service
		productMatch := (!existingProduct.Valid && event.Product == "") || (existingProduct.Valid && existingProduct.String == event.Product)
		versionMatch := (!existingVersion.Valid && event.Version == "") || (existingVersion.Valid && existingVersion.String == event.Version)
		bannerMatch := (!existingBanner.Valid && event.Banner == "") || (existingBanner.Valid && existingBanner.String == event.Banner)

		// If fingerprint is identical and not newer, skip processing
		// BUT: always process if we don't have fingerprint data yet (hasExistingFingerprint = false)
		if hasExistingFingerprint && serviceMatch && productMatch && versionMatch && bannerMatch && existingDetectedAt.Valid && detectedAt <= existingDetectedAt.Int64 {
			log.Debug().
				Str("ip", event.IP).
				Int("port", event.Port).
				Str("service", event.Service).
				Msg("Skipping duplicate fingerprint event (already processed)")
			return
		}
	}

	// 1. Ensure host exists in v2.0 schema
	if err := c.ensureHost(event.IP); err != nil {
		log.Error().Err(err).Str("ip", event.IP).Msg("Failed to ensure host exists")
	}

	// Debug: Log the raw fingerprint event data
	log.Debug().RawJSON("fingerprint_event", msg.Data).Msg("Raw fingerprint event received")
	log.Debug().Interface("certificates_pem", event.CertificatesPEM).Msg("Certificates PEM from event")

	// 2. Create enhanced fingerprint data JSON with TLS and certificate info
	fingerprintData := map[string]any{
		"service":          event.Service,
		"product":          event.Product,
		"version":          event.Version,
		"banner":           event.Banner,
		"detected_at":      detectedAt,
		"jarm_fingerprint": event.JARMFingerprint,
		"certificates_pem": event.CertificatesPEM,
	}
	fingerprintJSON, err := json.Marshal(fingerprintData)
	if err != nil {
		log.Error().Err(err).Msg("Failed to marshal fingerprint data")
		fingerprintJSON = []byte("{}")
	}

	// 3. Insert/update service in v2.0 schema with enhanced data
	// Only update if the new data is more recent OR if existing fields are empty/null

	// Compute banner_hash (SHA256 of banner)
	var bannerHash *string
	if event.Banner != "" {
		h := sha256.Sum256([]byte(event.Banner))
		bh := hex.EncodeToString(h[:])
		bannerHash = &bh
	}

	serviceQuery := `
		INSERT INTO services (ip, port, service, product, version, banner, banner_hash, fingerprint_data, detected_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(ip, port) DO UPDATE SET
			service = CASE
				WHEN excluded.detected_at > services.detected_at OR services.service IS NULL OR services.service = ''
				THEN excluded.service
				ELSE services.service
			END,
			product = CASE
				WHEN excluded.detected_at > services.detected_at OR services.product IS NULL OR services.product = ''
				THEN excluded.product
				ELSE services.product
			END,
			version = CASE
				WHEN excluded.detected_at > services.detected_at OR services.version IS NULL OR services.version = ''
				THEN excluded.version
				ELSE services.version
			END,
			banner = CASE
				WHEN excluded.detected_at > services.detected_at OR services.banner IS NULL OR services.banner = ''
				THEN excluded.banner
				ELSE services.banner
			END,
			banner_hash = CASE
				WHEN excluded.detected_at > services.detected_at OR services.banner_hash IS NULL OR services.banner_hash = ''
				THEN excluded.banner_hash
				ELSE services.banner_hash
			END,
			fingerprint_data = CASE
				WHEN excluded.detected_at > services.detected_at OR services.fingerprint_data IS NULL OR services.fingerprint_data = '{}'
				THEN excluded.fingerprint_data
				ELSE services.fingerprint_data
			END,
			detected_at = CASE
				WHEN excluded.detected_at > services.detected_at
				THEN excluded.detected_at
				ELSE services.detected_at
			END
	`
	_, err = c.db.Exec(serviceQuery, event.IP, event.Port, event.Service, event.Product, event.Version, event.Banner, bannerHash, string(fingerprintJSON), detectedAt)
	if err != nil {
		log.Error().Err(err).Msg("Failed to insert/update service")
		return
	}

	// 3b. Set enrichment_status based on whether this service will be enriched
	// Services with no name or 'tcpwrapped' will never receive enrichment results
	enrichStatus := StatusPending
	if event.Service == "" || event.Service == "tcpwrapped" {
		enrichStatus = StatusSkipped
	}
	if _, err := c.db.Exec(`UPDATE services SET enrichment_status = ?
		WHERE ip = ? AND port = ? AND (enrichment_status IS NULL OR enrichment_status = ?)`,
		enrichStatus, event.IP, event.Port, StatusPending); err != nil {
		log.Warn().Err(err).Str("ip", event.IP).Int("port", event.Port).Msg("Failed to set enrichment status")
	}

	// 4. Process certificates from fingerprint data (if available)
	log.Debug().Int("certificates_count", len(event.CertificatesPEM)).Msg("Checking certificates in fingerprint")
	if len(event.CertificatesPEM) > 0 {
		log.Debug().Str("ip", event.IP).Int("port", event.Port).Int("cert_count", len(event.CertificatesPEM)).Msg("Processing certificates from fingerprint")
		if err := c.processCertificatesFromFingerprint(event.IP, event.Port, event.CertificatesPEM, event.JARMFingerprint); err != nil {
			log.Error().Err(err).Msg("Failed to process certificates from fingerprint")
		} else {
			log.Debug().Str("ip", event.IP).Int("port", event.Port).Msg("Successfully processed certificates from fingerprint")
		}
	} else if isHTTPService(event.Service) {
		// For HTTP services (no TLS), create enrichments using existing domains for this host
		c.createHTTPEnrichmentsFromExistingDomains(event.IP, event.Port)
	}

	c.eventFeed.Push(RecentEvent{Type: "fingerprinted", IP: event.IP, Port: event.Port, Service: event.Service, Product: event.Product})

	log.Debug().
		Str("ip", event.IP).
		Int("port", event.Port).
		Str("service", event.Service).
		Str("jarm", event.JARMFingerprint).
		Int("certs", len(event.CertificatesPEM)).
		Msg("Stored fingerprint in services table")
}

// processCertificatesFromFingerprint processes certificates from fingerprint event data
func (c *Consumer) processCertificatesFromFingerprint(ip string, port int, certificatesPEM []string, jarmFingerprint string) error {
	log.Debug().Str("ip", ip).Int("port", port).Int("total_certs", len(certificatesPEM)).Msg("Starting processCertificatesFromFingerprint")

	for i, certPEM := range certificatesPEM {
		cert, err := parsePEMCertificate(certPEM, i)
		if err != nil {
			continue
		}

		fingerprint, err := c.insertCertificate(cert, certPEM)
		if err != nil {
			log.Error().Err(err).Str("fingerprint", fingerprint).Msg("Failed to insert certificate")
			continue
		}

		if err := c.linkCertToService(ip, port, fingerprint, i, jarmFingerprint); err != nil {
			log.Error().Err(err).Str("fingerprint", fingerprint).Msg("Failed to link certificate to service")
		}

		// Extract and store domains from leaf certificate only (i == 0)
		if i == 0 {
			c.extractAndStoreDomainsFromCert(ip, port, cert)
		}
	}

	return nil
}

// parsePEMCertificate decodes and parses a PEM-encoded certificate
func parsePEMCertificate(certPEM string, index int) (*x509.Certificate, error) {
	certBlock, _ := pem.Decode([]byte(certPEM))
	if certBlock == nil {
		log.Error().Int("index", index).Msg("Failed to decode PEM block")
		return nil, fmt.Errorf("failed to decode PEM block at index %d", index)
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		log.Error().Err(err).Int("index", index).Msg("Failed to parse certificate")
		return nil, err
	}
	log.Debug().Int("index", index).Str("subject_cn", cert.Subject.CommonName).Str("issuer_cn", cert.Issuer.CommonName).Msg("Parsed certificate")
	return cert, nil
}

// insertCertificate inserts a parsed certificate into the database, returns the SHA256 fingerprint
func (c *Consumer) insertCertificate(cert *x509.Certificate, certPEM string) (string, error) {
	// Generate fingerprints
	hash := sha256.Sum256(cert.Raw)
	fingerprint := hex.EncodeToString(hash[:])
	fingerprintSHA1 := calculateCertFingerprint(cert.Raw, crypto.SHA1)
	fingerprintMD5 := calculateCertFingerprint(cert.Raw, crypto.MD5)

	// Extract certificate information
	subjectCN := cert.Subject.CommonName
	issuerCN := cert.Issuer.CommonName

	var subjectOrg *string
	if len(cert.Subject.Organization) > 0 {
		subjectOrg = &cert.Subject.Organization[0]
	}

	var subjectCountry *string
	if len(cert.Subject.Country) > 0 {
		subjectCountry = &cert.Subject.Country[0]
	}

	var issuerOrg *string
	if len(cert.Issuer.Organization) > 0 {
		issuerOrg = &cert.Issuer.Organization[0]
	}

	// Build names array (CN + SANs)
	var names []string
	if cert.Subject.CommonName != "" {
		names = append(names, cert.Subject.CommonName)
	}
	names = append(names, cert.DNSNames...)

	var namesJSON *string
	if len(names) > 0 {
		namesBytes, err := json.Marshal(names)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to marshal certificate names")
		} else {
			namesStr := string(namesBytes)
			namesJSON = &namesStr
		}
	}

	// Check if certificate is self-signed
	isSelfSigned := 0
	if bytes.Equal(cert.RawSubject, cert.RawIssuer) && bytes.Equal(cert.SubjectKeyId, cert.AuthorityKeyId) {
		isSelfSigned = 1
	}

	// Check if certificate is a CA
	isCA := 0
	if cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign != 0 {
		isCA = 1
	}

	// Extract public key bits
	var publicKeyBits *int
	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		bits := key.N.BitLen()
		publicKeyBits = &bits
	case *ecdsa.PublicKey:
		bits := key.Curve.Params().BitSize
		publicKeyBits = &bits
	default:
		if cert.PublicKeyAlgorithm == x509.Ed25519 {
			bits := 256
			publicKeyBits = &bits
		}
	}

	// Extract serial number as hex string
	var serialNumber *string
	if cert.SerialNumber != nil {
		sn := cert.SerialNumber.Text(16)
		serialNumber = &sn
	}

	// Create parsed certificate JSON
	parsedCert := map[string]any{
		"subject":              cert.Subject,
		"issuer":               cert.Issuer,
		"serial_number":        cert.SerialNumber.String(),
		"signature_algorithm":  cert.SignatureAlgorithm.String(),
		"public_key_algorithm": cert.PublicKeyAlgorithm.String(),
		"dns_names":            cert.DNSNames,
		"email_addresses":      cert.EmailAddresses,
		"ip_addresses":         cert.IPAddresses,
		"uris":                 cert.URIs,
		"pem":                  certPEM,
	}
	parsedCertJSON, marshalErr := json.Marshal(parsedCert)
	if marshalErr != nil {
		log.Warn().Err(marshalErr).Msg("Failed to marshal parsed certificate JSON")
		parsedCertJSON = []byte("{}")
	}

	query := `
		INSERT OR IGNORE INTO certificates (
			fingerprint_sha256, fingerprint_sha1, fingerprint_md5,
			subject_cn, subject_org, subject_country,
			issuer_cn, issuer_org, names,
			not_before, not_after, serial_number,
			signature_algorithm, public_key_algorithm, public_key_bits,
			is_self_signed, is_ca, parsed_cert
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := c.db.Exec(query,
		fingerprint, fingerprintSHA1, fingerprintMD5,
		&subjectCN, subjectOrg, subjectCountry,
		&issuerCN, issuerOrg, namesJSON,
		cert.NotBefore.Unix(), cert.NotAfter.Unix(), serialNumber,
		cert.SignatureAlgorithm.String(), cert.PublicKeyAlgorithm.String(), publicKeyBits,
		isSelfSigned, isCA, string(parsedCertJSON))

	return fingerprint, err
}

// linkCertToService links a certificate to a service, with JARM for leaf certs
func (c *Consumer) linkCertToService(ip string, port int, fingerprint string, position int, jarmFingerprint string) error {
	query := `
		INSERT OR IGNORE INTO service_certificates (ip, port, cert_fingerprint, chain_position, jarm)
		VALUES (?, ?, ?, ?, ?)
	`
	var jarmPtr *string
	if jarmFingerprint != "" && position == 0 {
		jarmPtr = &jarmFingerprint
	}

	_, err := c.db.Exec(query, ip, port, fingerprint, position, jarmPtr)
	return err
}

// calculateCertFingerprint generates a fingerprint for a certificate using the given hash algorithm.
// Supported algorithms: crypto.SHA1, crypto.MD5.
func calculateCertFingerprint(rawCert []byte, algo crypto.Hash) *string {
	if len(rawCert) == 0 {
		return nil
	}
	h := algo.New()
	h.Write(rawCert)
	str := hex.EncodeToString(h.Sum(nil))
	return &str
}

// extractAndStoreDomainsFromCert extracts domains from certificate and stores them in host_domains
func (c *Consumer) extractAndStoreDomainsFromCert(ip string, port int, cert *x509.Certificate) {
	domains := make(map[string]bool)

	// Extract CN if it's a valid domain (not IP, not wildcard)
	if cert.Subject.CommonName != "" {
		cn := cert.Subject.CommonName
		if isValidDomain(cn) {
			domains[strings.ToLower(cn)] = true
		}
	}

	// Extract SANs (DNS Names)
	for _, san := range cert.DNSNames {
		if isValidDomain(san) {
			domains[strings.ToLower(san)] = true
		}
	}

	// Insert each domain into host_domains
	insertQuery := `
		INSERT INTO host_domains (ip, domain, source, discovered_port, first_seen, last_seen)
		VALUES (?, ?, 'certificate', ?, strftime('%s','now'), strftime('%s','now'))
		ON CONFLICT(ip, domain) DO UPDATE SET
			last_seen = strftime('%s','now'),
			discovered_port = COALESCE(discovered_port, excluded.discovered_port)
	`

	for domain := range domains {
		_, err := c.db.Exec(insertQuery, ip, domain, port)
		if err != nil {
			log.Warn().Err(err).Str("ip", ip).Str("domain", domain).Msg("Failed to insert host_domain")
		} else {
			log.Debug().Str("ip", ip).Str("domain", domain).Int("port", port).Msg("Stored domain from certificate")
		}
	}

	// Filter out domains that have been seen on too many IPs (default cert suppression)
	domainsToEnrich := c.filterHighFrequencyDomains(ip, domains)

	// Create pending enrichments for this TLS port
	if len(domainsToEnrich) > 0 {
		c.createPendingHTTPEnrichments(ip, port, domainsToEnrich)

		// Also create enrichments for HTTP port 80 if it exists for this host
		c.createHTTPEnrichmentsForExistingPort(ip, 80, domainsToEnrich)
	}
}

// filterHighFrequencyDomains increments the per-domain IP counter and returns only
// domains that are below the enrichment threshold. Domains from widely-shared default
// certificates (seen on many IPs) are filtered out to avoid an enrichment job surge.
// The domain is still stored in host_domains regardless.
func (c *Consumer) filterHighFrequencyDomains(ip string, domains map[string]bool) map[string]bool {
	threshold := c.cfg.DomainEnrichThreshold
	if threshold <= 0 {
		return domains
	}

	c.domainIPCountMu.Lock()
	defer c.domainIPCountMu.Unlock()

	filtered := make(map[string]bool, len(domains))
	for domain := range domains {
		c.domainIPCount[domain]++
		count := c.domainIPCount[domain]
		if count <= threshold {
			filtered[domain] = true
		} else if count == threshold+1 {
			// Log once when threshold is crossed
			log.Warn().
				Str("domain", domain).
				Int("ip_count", count).
				Int("threshold", threshold).
				Str("ip", ip).
				Msg("Domain exceeded enrichment threshold, skipping future enrichments (likely default cert)")
		}
	}

	if skipped := len(domains) - len(filtered); skipped > 0 {
		log.Debug().
			Str("ip", ip).
			Int("total_domains", len(domains)).
			Int("skipped", skipped).
			Int("threshold", threshold).
			Msg("Filtered high-frequency domains from enrichment")
	}

	return filtered
}

// createHTTPEnrichmentsForExistingPort creates enrichments for HTTP port if it exists
func (c *Consumer) createHTTPEnrichmentsForExistingPort(ip string, port int, domains map[string]bool) {
	// Check if this port exists for this host
	var exists int
	err := c.db.QueryRow(`SELECT 1 FROM services WHERE ip = ? AND port = ?`, ip, port).Scan(&exists)
	if err != nil {
		// Port doesn't exist yet, skip
		return
	}

	log.Debug().Str("ip", ip).Int("port", port).Int("domains", len(domains)).Msg("Creating HTTP enrichments for existing port from new domains")
	c.createPendingHTTPEnrichments(ip, port, domains)
}

// isValidDomain checks if a string is a valid domain (not IP, not wildcard, has at least one dot)
func isValidDomain(s string) bool {
	if s == "" {
		return false
	}

	// Skip wildcards
	if strings.HasPrefix(s, "*") {
		return false
	}

	// Skip IP addresses
	if net.ParseIP(s) != nil {
		return false
	}

	// Must contain at least one dot
	if !strings.Contains(s, ".") {
		return false
	}

	// Skip localhost
	if s == "localhost" || strings.HasSuffix(s, ".localhost") {
		return false
	}

	return true
}

// createHTTPEnrichmentsFromExistingDomains creates HTTP enrichments using domains already discovered for this host
func (c *Consumer) createHTTPEnrichmentsFromExistingDomains(ip string, port int) {
	// Query existing domains for this host
	query := `SELECT domain FROM host_domains WHERE ip = ?`
	rows, err := c.db.Query(query, ip)
	if err != nil {
		log.Warn().Err(err).Str("ip", ip).Msg("Failed to query host domains for HTTP enrichment")
		return
	}
	defer rows.Close()

	domains := make(map[string]bool)
	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err == nil && domain != "" {
			domains[domain] = true
		}
	}
	if err := rows.Err(); err != nil {
		log.Warn().Err(err).Str("ip", ip).Msg("Error iterating host domains rows")
	}

	if len(domains) > 0 {
		log.Debug().Str("ip", ip).Int("port", port).Int("domains", len(domains)).Msg("Creating HTTP enrichments from existing domains")
		c.createPendingHTTPEnrichments(ip, port, domains)
	} else {
		// No domains yet, just create enrichment for direct IP
		insertQuery := `
			INSERT INTO service_enrichments (ip, port, domain, status, created_at)
			VALUES (?, ?, '', 'pending', strftime('%s','now'))
			ON CONFLICT(ip, port, domain) DO UPDATE SET
				created_at = strftime('%s','now')
			WHERE service_enrichments.status IN ('pending', 'failed')
		`
		if _, err := c.db.Exec(insertQuery, ip, port); err != nil {
			log.Warn().Err(err).Str("ip", ip).Int("port", port).Msg("Failed to create pending enrichment for direct IP")
		}
	}
}

// createPendingHTTPEnrichments creates pending enrichment entries for HTTP/HTTPS services
// Creates one enrichment per domain (using SNI/Host header) plus one for direct IP access
// Only processes HTTP/HTTPS services (skips SMTP, IMAP, etc.)
func (c *Consumer) createPendingHTTPEnrichments(ip string, port int, domains map[string]bool) {
	// Get the fingerprinted service type from the services table
	var serviceType string
	err := c.db.QueryRow(`SELECT COALESCE(service, '') FROM services WHERE ip = ? AND port = ?`, ip, port).Scan(&serviceType)
	if err != nil {
		log.Debug().Str("ip", ip).Int("port", port).Msg("Service not found, skipping HTTP enrichment")
		return
	}

	// Only process HTTP/HTTPS services - skip SMTP, IMAP, POP3, etc.
	if !isHTTPService(serviceType) {
		log.Debug().Str("ip", ip).Int("port", port).Str("service", serviceType).Msg("Skipping HTTP enrichment for non-HTTP service")
		return
	}

	insertQuery := `
		INSERT INTO service_enrichments (ip, port, domain, status, created_at)
		VALUES (?, ?, ?, 'pending', strftime('%s','now'))
		ON CONFLICT(ip, port, domain) DO UPDATE SET
			created_at = strftime('%s','now')
		WHERE service_enrichments.status IN ('pending', 'failed')
	`

	// Create enrichment for direct IP access (empty string = no SNI)
	// Direct IP enrichment is already triggered by normal fingerprinting flow, no need to publish again
	_, err = c.db.Exec(insertQuery, ip, port, "")
	if err != nil {
		log.Warn().Err(err).Str("ip", ip).Int("port", port).Msg("Failed to create pending enrichment for direct IP")
	}

	// Create enrichment for each domain and publish NATS request
	for domain := range domains {
		// Insert pending entry in database (or reset pending/failed ones for retry)
		result, err := c.db.Exec(insertQuery, ip, port, domain)
		if err != nil {
			log.Warn().Err(err).Str("ip", ip).Str("domain", domain).Msg("Failed to create pending enrichment")
			continue
		}

		// rowsAffected > 0 means new record OR pending/failed record was reset
		// rowsAffected == 0 means already enriched successfully, skip republishing
		rowsAffected, err := result.RowsAffected()
		if err != nil {
			log.Warn().Err(err).Str("ip", ip).Str("domain", domain).Msg("Failed to get rows affected for enrichment insert")
		}
		if rowsAffected == 0 {
			// Already enriched, skip publishing
			log.Debug().Str("ip", ip).Str("domain", domain).Int("port", port).Msg("Domain enrichment already completed, skipping")
			continue
		}

		// Publish NATS request to trigger grabber enrichment with SNI/Host header
		c.publishEnrichmentRequest(ip, port, serviceType, domain)

		log.Debug().Str("ip", ip).Str("domain", domain).Int("port", port).Msg("Created and published domain enrichment request")
	}
}

// publishEnrichmentRequest publishes an enrichment request to NATS for the grabber to process
func (c *Consumer) publishEnrichmentRequest(ip string, port int, service, domain string) {
	if c.nc == nil {
		log.Warn().Msg("NATS connection not available, cannot publish enrichment request")
		return
	}

	// Build enrichment request matching grabber's EnrichmentRequest structure
	request := struct {
		IP      string `json:"ip"`
		Port    int    `json:"port"`
		Service string `json:"service"`
		Domain  string `json:"domain,omitempty"`
	}{
		IP:      ip,
		Port:    port,
		Service: service,
		Domain:  domain,
	}

	data, err := json.Marshal(request)
	if err != nil {
		log.Error().Err(err).Str("ip", ip).Str("domain", domain).Msg("Failed to marshal enrichment request")
		return
	}

	// Publish to dedicated enrichment request topic (not fingerprinted, to avoid feedback loop)
	err = c.nc.Publish(TopicEnrichRequest, data)
	if err != nil {
		log.Error().Err(err).Str("ip", ip).Str("domain", domain).Msg("Failed to publish enrichment request")
		return
	}

	log.Info().
		Str("ip", ip).
		Int("port", port).
		Str("service", service).
		Str("domain", domain).
		Msg("Published enrichment request to NATS")
}

// isHTTPService checks if a service is HTTP/HTTPS (including ssl/http variants)
func isHTTPService(service string) bool {
	return service == "http" || service == "https" || service == "ssl/http"
}
