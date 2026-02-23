package main

import (
	"encoding/binary"
	"encoding/json"
	"net"

	"github.com/nats-io/nats.go"
	"github.com/rs/zerolog/log"
)

func (c *Consumer) handleOpenPort(msg *nats.Msg) {
	var event OpenPortEvent
	if err := json.Unmarshal(msg.Data, &event); err != nil {
		log.Error().Err(err).Str("raw_message", string(msg.Data)).Msg("Failed to unmarshal open port event")
		return
	}

	detectedAt := int64(event.Timestamp)

	// 1. Ensure host exists in v2.0 schema
	if err := c.ensureHost(event.IP); err != nil {
		log.Error().Err(err).Str("ip", event.IP).Msg("Failed to ensure host exists")
	}

	// 2. Insert/update service in v2.0 schema (without fingerprint data yet)
	// Always update to the most recent timestamp
	// enrichment_status = NULL: not yet fingerprinted, enrichability unknown
	serviceQuery := `
		INSERT INTO services (ip, port, detected_at, enrichment_status)
		VALUES (?, ?, ?, NULL)
		ON CONFLICT(ip, port) DO UPDATE SET
			detected_at = CASE WHEN excluded.detected_at > detected_at THEN excluded.detected_at ELSE detected_at END
	`
	_, err := c.db.Exec(serviceQuery, event.IP, event.Port, detectedAt)
	if err != nil {
		log.Error().Err(err).Msg("Failed to insert/update service")
		return
	}

	c.eventFeed.Push(RecentEvent{Type: "open", IP: event.IP, Port: event.Port})

	log.Debug().
		Str("ip", event.IP).
		Int("port", event.Port).
		Msg("Stored open port in services table")

	// Note: The datastore is a passive component - it only stores data.
	// Fingerprinting is automatically triggered by the grabber service which
	// also subscribes to scan.port.open. We do NOT republish here to avoid
	// duplicate fingerprint requests.
}

// ensureHost creates host entry with GeoIP data if it doesn't exist
func (c *Consumer) ensureHost(ip string) error {
	// Get GeoIP data
	countryCode, countryName, city, timezone, asn, asOrg, isp, cloudProvider, cloudRegion, cloudType := c.enrichHostWithGeoIP(ip)

	// Convert to pointers for nullable fields
	var asnPtr *int
	if asn != nil {
		asnPtr = asn
	}

	// Compute ip_int for CIDR range queries
	var ipInt *uint32
	if parsed := net.ParseIP(ip); parsed != nil {
		if v4 := parsed.To4(); v4 != nil {
			n := binary.BigEndian.Uint32(v4)
			ipInt = &n
		}
	}

	query := `
		INSERT INTO hosts (
			ip, ip_int, country_code, country_name, city, timezone,
			asn, as_org, isp, cloud_provider, cloud_region, cloud_type
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(ip) DO UPDATE SET
			ip_int = COALESCE(hosts.ip_int, excluded.ip_int)
	`
	_, err := c.db.Exec(query, ip, ipInt, countryCode, countryName, city, timezone,
		asnPtr, asOrg, isp, cloudProvider, cloudRegion, cloudType)
	return err
}
