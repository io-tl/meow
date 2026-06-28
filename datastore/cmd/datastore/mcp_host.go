package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
)

// ---------------------------------------------------------------------------
// meow_host — Detailed host information
// ---------------------------------------------------------------------------

func (h *mcpHandler) handleHost(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	ip, err := req.RequireString("ip")
	if err != nil {
		return mcp.NewToolResultError("ip parameter required"), nil
	}
	if net.ParseIP(ip) == nil {
		return mcp.NewToolResultError(fmt.Sprintf("invalid IP address: %s", ip)), nil
	}

	// Host info
	var countryCode, countryName, city, cloudProvider, cloudRegion, asOrg sql.NullString
	var asn, firstSeen, lastScan, openPorts, svcCount sql.NullInt64
	err = h.db.QueryRowContextLogged(ctx, `
		SELECT country_code, country_name, city, asn, as_org, cloud_provider, cloud_region,
		       first_seen, last_scan, open_ports_count, services_count
		FROM hosts WHERE ip = ?`, ip).Scan(
		&countryCode, &countryName, &city, &asn, &asOrg, &cloudProvider, &cloudRegion,
		&firstSeen, &lastScan, &openPorts, &svcCount)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("host %s not found", ip)), nil
	}

	host := map[string]any{"ip": ip}
	setNullStr(host, "country_code", countryCode)
	setNullStr(host, "country_name", countryName)
	setNullStr(host, "city", city)
	setIfValidInt(host, "asn", asn)
	setNullStr(host, "as_org", asOrg)
	setNullStr(host, "cloud_provider", cloudProvider)
	setNullStr(host, "cloud_region", cloudRegion)
	setIfValidInt(host, "first_seen", firstSeen)
	setIfValidInt(host, "last_scan", lastScan)
	setIfValidInt(host, "open_ports_count", openPorts)
	setIfValidInt(host, "services_count", svcCount)

	// Sections filtering
	sections := parseFieldsParam(req.GetString("sections", ""))
	fields := req.GetString("fields", "")

	if sections == nil || sections["services"] {
		host["services"] = h.queryServices(ctx, ip, fields)
	}
	if sections == nil || sections["certificates"] {
		host["certificates"] = h.queryCertificates(ctx, ip, fields)
	}
	if sections == nil || sections["domains"] {
		host["domains"] = h.queryDomains(ctx, ip)
	}

	return mcpEnvelope("meow_host", []map[string]any{host}, false)
}

func (h *mcpHandler) queryServices(ctx context.Context, ip string, fields string) []map[string]any {
	rows, err := h.db.QueryContext(ctx, `
		SELECT s.port, s.service, s.product, s.version, s.banner,
		       s.enrichment_status, s.enrichment_data,
		       hd.status_code, hd.title, hd.server, hd.technologies, hd.cms, hd.framework
		FROM services s
		LEFT JOIN http_data hd ON s.ip = hd.ip AND s.port = hd.port
		WHERE s.ip = ? ORDER BY s.port`, ip)
	if err != nil {
		return nil
	}
	defer rows.Close()

	svcDefaults := []string{
		"port", "service", "product", "version",
		"enrichment.anonymous_login", "enrichment.auth_required", "enrichment.signing_required",
		"enrichment.default_credentials", "enrichment.tls", "enrichment.protocol", "enrichment.version",
	}
	fieldSet := resolveFields(fields, svcDefaults)
	wantEnrichment := hasFieldPrefix(fieldSet, "enrichment.")

	var services []map[string]any
	for rows.Next() {
		var port int
		var svcName, product, version, banner, enrichStatus sql.NullString
		var enrichData sql.NullString
		var httpStatus sql.NullInt64
		var httpTitle, httpServer, httpTech, httpCMS, httpFramework sql.NullString

		if err := rows.Scan(&port, &svcName, &product, &version, &banner,
			&enrichStatus, &enrichData,
			&httpStatus, &httpTitle, &httpServer, &httpTech, &httpCMS, &httpFramework); err != nil {
			continue
		}

		svc := map[string]any{"port": port}
		setNullStr(svc, "service", svcName)
		setNullStr(svc, "product", product)
		setNullStr(svc, "version", version)
		setSanitizedBanner(svc, "banner", banner)
		setNullStr(svc, "enrichment", enrichStatus)
		setIfValidInt(svc, "http_status", httpStatus)
		setNullStr(svc, "http_title", httpTitle)
		setNullStr(svc, "http_server", httpServer)
		setNullStr(svc, "cms", httpCMS)
		setNullStr(svc, "framework", httpFramework)

		// Parse enrichment_data JSON for key fields
		if wantEnrichment && enrichData.Valid && enrichData.String != "" && enrichData.String != "{}" {
			var ed map[string]any
			if json.Unmarshal([]byte(enrichData.String), &ed) == nil {
				for _, key := range []string{
					"anonymous_login", "auth_required", "signing_required",
					"default_credentials", "tls", "protocol", "version",
				} {
					if v, ok := ed[key]; ok {
						svc["enrichment."+key] = v
					}
				}
			}
		}

		services = append(services, filterRow(svc, fieldSet))
	}
	// rows.Err() intentionally not returned — sub-query helper, partial results acceptable
	return services
}

func (h *mcpHandler) queryCertificates(ctx context.Context, ip string, fields string) []map[string]any {
	rows, err := h.db.QueryContext(ctx, `
		SELECT c.fingerprint_sha256, c.subject_cn, c.issuer_cn, c.names,
		       c.not_before, c.not_after, c.is_self_signed,
		       c.public_key_algorithm, c.public_key_bits,
		       sc.jarm, sc.port
		FROM certificates c
		JOIN service_certificates sc ON c.fingerprint_sha256 = sc.cert_fingerprint
		WHERE sc.ip = ? AND sc.chain_position = 0
		ORDER BY sc.port`, ip)
	if err != nil {
		return nil
	}
	defer rows.Close()

	certDefaults := []string{"port", "fingerprint", "subject_cn", "issuer_cn", "self_signed", "expired"}
	fieldSet := resolveFields(fields, certDefaults)

	now := time.Now().Unix()
	var certs []map[string]any
	for rows.Next() {
		var fingerprint, subjectCN, issuerCN, names sql.NullString
		var notBefore, notAfter sql.NullInt64
		var selfSigned sql.NullInt64
		var algo sql.NullString
		var bits sql.NullInt64
		var jarm sql.NullString
		var port int

		if err := rows.Scan(&fingerprint, &subjectCN, &issuerCN, &names,
			&notBefore, &notAfter, &selfSigned,
			&algo, &bits, &jarm, &port); err != nil {
			continue
		}

		cert := map[string]any{"port": port}
		setNullStr(cert, "fingerprint", fingerprint)
		setNullStr(cert, "subject_cn", subjectCN)
		setNullStr(cert, "issuer_cn", issuerCN)
		setNullStr(cert, "names", names)
		setNullStr(cert, "algorithm", algo)
		setIfValidInt(cert, "bits", bits)
		setNullStr(cert, "jarm", jarm)
		if selfSigned.Valid && selfSigned.Int64 == 1 {
			cert["self_signed"] = true
		}
		if notAfter.Valid {
			cert["not_after"] = notAfter.Int64
			if notAfter.Int64 < now {
				cert["expired"] = true
			}
		}
		certs = append(certs, filterRow(cert, fieldSet))
	}
	return certs
}

func (h *mcpHandler) queryDomains(ctx context.Context, ip string) []map[string]any {
	rows, err := h.db.QueryContext(ctx, `
		SELECT domain, source, discovered_port
		FROM host_domains WHERE ip = ? ORDER BY last_seen DESC`, ip)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var domains []map[string]any
	for rows.Next() {
		var domain, source sql.NullString
		var port sql.NullInt64
		if err := rows.Scan(&domain, &source, &port); err != nil {
			continue
		}
		d := map[string]any{}
		setNullStr(d, "domain", domain)
		setNullStr(d, "source", source)
		setIfValidInt(d, "port", port)
		domains = append(domains, d)
	}
	return domains
}
