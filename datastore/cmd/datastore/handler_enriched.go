package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/rs/zerolog/log"
)

func (c *Consumer) handleEnriched(msg *nats.Msg) {
	var event EnrichmentEvent
	if err := json.Unmarshal(msg.Data, &event); err != nil {
		log.Error().Err(err).Str("raw_message", string(msg.Data)).Msg("Failed to unmarshal enrichment event")
		return
	}

	log.Debug().
		Str("ip", event.IP).
		Int("port", event.Port).
		Str("service", event.Service).
		Str("domain", event.Domain).
		Msg("Processing enrichment event")

	// Parse timestamp
	var enrichedAt int64
	if event.Timestamp != "" {
		t, err := time.Parse(time.RFC3339Nano, event.Timestamp)
		if err == nil {
			enrichedAt = t.Unix()
		} else {
			log.Warn().Err(err).Str("timestamp", event.Timestamp).Msg("Failed to parse enrichment timestamp, using current time")
		}
	}
	if enrichedAt == 0 {
		enrichedAt = time.Now().Unix()
	}

	// Determine enrichment status
	status := StatusEnriched
	if event.Error != "" {
		status = StatusFailed
	}

	// Early duplicate detection: check if we already have this enrichment
	var existingStatus sql.NullString
	var existingEnrichedAt sql.NullInt64
	domainValue := event.Domain
	err := c.db.QueryRow(`
		SELECT status, enriched_at
		FROM service_enrichments
		WHERE ip = ? AND port = ? AND domain = ?`,
		event.IP, event.Port, domainValue).Scan(&existingStatus, &existingEnrichedAt)

	if err != nil && err != sql.ErrNoRows {
		log.Error().Err(err).Str("ip", event.IP).Int("port", event.Port).Msg("DB error during enrichment duplicate check")
		return
	}
	if err == nil {
		// Enrichment exists, check if status is identical and timestamp is not newer
		statusMatch := existingStatus.Valid && existingStatus.String == status
		if statusMatch && existingEnrichedAt.Valid && enrichedAt <= existingEnrichedAt.Int64 {
			log.Debug().
				Str("ip", event.IP).
				Int("port", event.Port).
				Str("domain", event.Domain).
				Str("status", status).
				Msg("Skipping duplicate enrichment event (already processed)")
			return
		}
	}

	// Debug: Log the enrichment data structure
	log.Debug().Interface("enrichment_data", event.Data).Msg("Processing enrichment data")
	log.Debug().RawJSON("raw_enrichment_event", msg.Data).Msg("Raw enrichment event received")

	// Marshal enrichment data to JSON
	var enrichmentDataJSON []byte
	if event.Data != nil {
		var err error
		enrichmentDataJSON, err = json.Marshal(event.Data)
		if err != nil {
			log.Error().Err(err).Msg("Failed to marshal enrichment data")
			enrichmentDataJSON = []byte("{}")
		}
	}

	// 1. Ensure host exists
	if err := c.ensureHost(event.IP); err != nil {
		log.Error().Err(err).Str("ip", event.IP).Msg("Failed to ensure host exists")
	}

	// 1b. Ensure service exists (fixes FK race: enriched can arrive before fingerprinted)
	if err := c.ensureService(event.IP, event.Port, event.Service); err != nil {
		log.Error().Err(err).Str("ip", event.IP).Int("port", event.Port).Msg("Failed to ensure service exists")
	}

	// 2. Upsert service with enrichment data (legacy - keeps backward compatibility)
	if err := c.upsertServiceEnrichment(event.IP, event.Port, event.Service, string(enrichmentDataJSON), status, enrichedAt); err != nil {
		log.Error().Err(err).Msg("Failed to upsert service enrichment")
		return
	}

	// 3. Store in service_enrichments table (supports multi-domain via SNI for HTTPS)
	if err := c.upsertServiceEnrichmentRecord(event.IP, event.Port, event.Domain, event.Data, enrichmentDataJSON, status, event.Error, enrichedAt); err != nil {
		log.Error().Err(err).Msg("Failed to upsert service enrichment")
	}

	// 4. Process HTTP-specific data if service is http/https
	if isHTTPService(event.Service) && status == "enriched" {
		if err := c.processHTTPData(event.IP, event.Port, event.Data, enrichedAt); err != nil {
			log.Error().Err(err).Msg("Failed to process HTTP data")
		}
	}

	c.eventFeed.Push(RecentEvent{Type: "enriched", IP: event.IP, Port: event.Port, Service: event.Service})

	log.Debug().
		Str("ip", event.IP).
		Int("port", event.Port).
		Str("domain", event.Domain).
		Str("status", status).
		Msg("Enrichment stored successfully")
}

// upsertServiceEnrichment updates service with enrichment data
// Only updates existing services - does NOT create new services
// Services must be created by fingerprinting first (handleFingerprinted)
func (c *Consumer) upsertServiceEnrichment(ip string, port int, service, enrichmentData, status string, enrichedAt int64) error {
	// Only UPDATE existing services, don't INSERT new ones
	// A service must exist from fingerprinting before it can be enriched
	// Only update if the new data is more recent OR if existing enrichment data is empty/null
	query := `
		UPDATE services SET
			enrichment_data = CASE
				WHEN ? > COALESCE(enriched_at, 0) OR enrichment_data IS NULL OR enrichment_data = '{}'
				THEN ?
				ELSE enrichment_data
			END,
			enrichment_status = CASE
				WHEN ? > COALESCE(enriched_at, 0) OR enrichment_status IS NULL OR enrichment_status = ''
				THEN ?
				ELSE enrichment_status
			END,
			enriched_at = CASE
				WHEN ? > COALESCE(enriched_at, 0)
				THEN ?
				ELSE enriched_at
			END
		WHERE ip = ? AND port = ?
	`
	result, err := c.db.Exec(query, enrichedAt, enrichmentData, enrichedAt, status, enrichedAt, enrichedAt, ip, port)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		log.Warn().Err(err).Str("ip", ip).Int("port", port).Msg("Failed to get rows affected for service enrichment update")
	} else if rowsAffected == 0 {
		log.Warn().
			Str("ip", ip).
			Int("port", port).
			Str("service", service).
			Msg("Enrichment received for non-existent service (not fingerprinted yet)")
	}

	return nil
}

// upsertServiceEnrichmentRecord stores enrichment data in the service_enrichments table
// Supports multiple domains per service (via SNI for HTTPS, empty for other protocols)
// preMarshaled is the already-marshaled JSON of data (avoids double marshal).
func (c *Consumer) upsertServiceEnrichmentRecord(ip string, port int, domain string, data any, preMarshaled []byte, status string, errorMsg string, enrichedAt int64) error {
	enrichmentDataJSON := preMarshaled

	// Extract generic fields for denormalization (all protocols)
	var protocol, version, bannerVal *string
	var statusCode *int
	var title, server, redirectURL *string
	var contentLength *int

	if dataMap, ok := data.(map[string]any); ok {
		// Generic fields (all protocols)
		if p, ok := dataMap["protocol"].(string); ok && p != "" {
			protocol = &p
		}
		if v, ok := dataMap["version"].(string); ok && v != "" {
			version = &v
		}
		if b, ok := dataMap["banner"].(string); ok && b != "" {
			bannerVal = &b
		}

		// HTTP-specific fields
		// Status code
		if sc, ok := dataMap["status_code"].(float64); ok {
			scInt := int(sc)
			statusCode = &scInt
		}

		// Title
		if t, ok := dataMap["title"].(string); ok && t != "" {
			title = &t
		}

		// Server header
		if headers, ok := dataMap["headers"].(map[string]any); ok {
			if serverHeader, ok := headers["Server"].([]any); ok && len(serverHeader) > 0 {
				if s, ok := serverHeader[0].(string); ok {
					server = &s
				}
			}
			// Location header (redirect)
			if locHeader, ok := headers["Location"].([]any); ok && len(locHeader) > 0 {
				if loc, ok := locHeader[0].(string); ok {
					redirectURL = &loc
				}
			}
		}

		// Content length
		if cl, ok := dataMap["body_length"].(float64); ok {
			clInt := int(cl)
			contentLength = &clInt
		}
	}

	// Use empty string for domain when not specified (SQLite primary key)
	domainValue := domain

	query := `
		INSERT INTO service_enrichments (ip, port, domain, enrichment_data,
			protocol, version, banner,
			status_code, title, server, redirect_url, content_length,
			status, error, enriched_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(ip, port, domain) DO UPDATE SET
			enrichment_data = excluded.enrichment_data,
			protocol = excluded.protocol,
			version = excluded.version,
			banner = excluded.banner,
			status_code = excluded.status_code,
			title = excluded.title,
			server = excluded.server,
			redirect_url = excluded.redirect_url,
			content_length = excluded.content_length,
			status = excluded.status,
			error = excluded.error,
			enriched_at = excluded.enriched_at
	`

	var errorPtr *string
	if errorMsg != "" {
		errorPtr = &errorMsg
	}

	_, err := c.db.Exec(query, ip, port, domainValue, string(enrichmentDataJSON),
		protocol, version, bannerVal,
		statusCode, title, server, redirectURL, contentLength,
		status, errorPtr, enrichedAt)
	if err != nil {
		return fmt.Errorf("failed to upsert service enrichment: %w", err)
	}

	log.Debug().
		Str("ip", ip).
		Int("port", port).
		Str("domain", domain).
		Str("status", status).
		Msg("Stored service enrichment")

	return nil
}

// processHTTPData extracts and stores HTTP-specific enrichment data
func (c *Consumer) processHTTPData(ip string, port int, data any, scannedAt int64) error {
	// Parse data as map to extract HTTP fields
	dataMap, ok := data.(map[string]any)
	if !ok {
		return fmt.Errorf("enrichment data is not a map")
	}

	// Extract HTTP fields
	var statusCode *int
	var server, title, cms, framework, webserver, faviconMD5 *string
	var bodyPreview, bodyHash, redirectsTo *string
	var headers, technologies any
	var useSSL int

	if sc, ok := dataMap["status_code"].(float64); ok {
		scInt := int(sc)
		statusCode = &scInt
	}

	if proto, ok := dataMap["protocol"].(string); ok && proto == "https" {
		useSSL = 1
	}

	// Extract headers
	if h, ok := dataMap["headers"]; ok {
		headers = h
	}

	// Extract technologies and derive cms/framework/webserver
	if t, ok := dataMap["technologies"]; ok {
		technologies = t
		if techList, ok := t.([]any); ok {
			for _, item := range techList {
				tech, ok := item.(map[string]any)
				if !ok {
					continue
				}
				name, _ := tech["name"].(string)
				cats, _ := tech["categories"].([]any)
				for _, cat := range cats {
					catMap, ok := cat.(map[string]any)
					if !ok {
						continue
					}
					catName, _ := catMap["name"].(string)
					switch catName {
					case "CMS":
						if cms == nil {
							cms = &name
						}
					case "Web frameworks", "JavaScript frameworks":
						if framework == nil {
							framework = &name
						}
					case "Web servers":
						if webserver == nil {
							webserver = &name
						}
					}
				}
			}
		}
	}

	// Extract title from HTML body
	if body, ok := dataMap["body"].(string); ok {
		if extracted := extractHTMLTitle(body); extracted != "" {
			title = &extracted
		}
		// Store body preview (first 1KB)
		preview := body
		if len(preview) > 1024 {
			preview = preview[:1024]
		}
		bodyPreview = &preview
		// Compute body_hash (SHA256)
		if body != "" {
			h := sha256.Sum256([]byte(body))
			bh := hex.EncodeToString(h[:])
			bodyHash = &bh
		}
	}

	// Extract redirect URL
	if redirects, ok := dataMap["redirects"].([]any); ok && len(redirects) > 0 {
		if last, ok := redirects[len(redirects)-1].(string); ok {
			redirectsTo = &last
		}
	}

	// Extract favicon MD5
	if fav, ok := dataMap["favicon"].(map[string]any); ok {
		if md5, ok := fav["md5"].(string); ok && md5 != "" {
			faviconMD5 = &md5
		}
	}

	// Try to extract Server from headers
	if headersMap, ok := headers.(map[string]any); ok {
		if serverHeader, ok := headersMap["Server"].([]any); ok && len(serverHeader) > 0 {
			if s, ok := serverHeader[0].(string); ok {
				server = &s
			}
		}
	}

	// Marshal headers and technologies to JSON
	var headersJSON, techJSON []byte
	if headers != nil {
		var err error
		headersJSON, err = json.Marshal(headers)
		if err != nil {
			log.Warn().Err(err).Str("ip", ip).Int("port", port).Msg("Failed to marshal HTTP headers")
		}
	}
	if technologies != nil {
		var err error
		techJSON, err = json.Marshal(technologies)
		if err != nil {
			log.Warn().Err(err).Str("ip", ip).Int("port", port).Msg("Failed to marshal technologies")
		}
	}

	// Insert or update http_data
	query := `
		INSERT INTO http_data (
			ip, port, status_code, server, title, body_hash, body_preview, headers, technologies,
			cms, framework, webserver, uses_ssl, favicon_md5, redirects_to, scanned_at
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(ip, port) DO UPDATE SET
			status_code = excluded.status_code,
			server = excluded.server,
			title = excluded.title,
			body_hash = excluded.body_hash,
			body_preview = excluded.body_preview,
			headers = excluded.headers,
			technologies = excluded.technologies,
			cms = excluded.cms,
			framework = excluded.framework,
			webserver = excluded.webserver,
			uses_ssl = excluded.uses_ssl,
			favicon_md5 = excluded.favicon_md5,
			redirects_to = excluded.redirects_to,
			scanned_at = excluded.scanned_at
	`

	_, err := c.db.Exec(query,
		ip, port, statusCode, server, title, bodyHash, bodyPreview,
		stringOrNil(headersJSON), stringOrNil(techJSON),
		cms, framework, webserver, useSSL, faviconMD5, redirectsTo, scannedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to insert http_data: %w", err)
	}

	return nil
}

// ensureService creates a minimal service placeholder if it doesn't exist yet.
// This prevents FK violations when enriched events arrive before fingerprinted events.
// When handleFingerprinted arrives later, its INSERT ... ON CONFLICT DO UPDATE will
// fill in the real data (product, version, banner, etc.).
func (c *Consumer) ensureService(ip string, port int, service string) error {
	query := `INSERT OR IGNORE INTO services (ip, port, service, detected_at) VALUES (?, ?, ?, strftime('%s','now'))`
	_, err := c.db.Exec(query, ip, port, service)
	return err
}

// extractHTMLTitle extracts the content of the first <title> tag from HTML.
func extractHTMLTitle(html string) string {
	lower := strings.ToLower(html)
	start := strings.Index(lower, "<title")
	if start == -1 {
		return ""
	}
	// Skip past the tag attributes and closing >
	gt := strings.Index(lower[start:], ">")
	if gt == -1 {
		return ""
	}
	contentStart := start + gt + 1
	end := strings.Index(lower[contentStart:], "</title>")
	if end == -1 {
		return ""
	}
	title := strings.TrimSpace(html[contentStart : contentStart+end])
	if len(title) > 512 {
		title = title[:512]
	}
	return title
}
