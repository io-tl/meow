package main

import (
	"database/sql"
	"encoding/json"
	"sort"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

// queryValueCounts executes a query that returns (value string, count int) rows
// and returns a slice of gin.H with the given key name for the value.
func (api *API) queryValueCounts(query string, valueKey string) []gin.H {
	rows, err := api.db.Query(query)
	if err != nil {
		log.Warn().Err(err).Str("query_key", valueKey).Msg("Failed to query value counts")
		return nil
	}
	defer rows.Close()

	var results []gin.H
	for rows.Next() {
		var value string
		var count int
		if err := rows.Scan(&value, &count); err != nil {
			continue
		}
		results = append(results, gin.H{valueKey: value, "count": count})
	}
	if err := rows.Err(); err != nil {
		log.Warn().Err(err).Str("query_key", valueKey).Msg("Error iterating value count rows")
	}
	return results
}

// getDashboardStats gets dashboard statistics
func (api *API) getDashboardStats(c *gin.Context) {
	stats := gin.H{}

	// Total counts
	totalHosts, totalServices, totalCerts, _ := api.db.getTableCounts()
	stats["total_hosts"] = totalHosts
	stats["total_services"] = totalServices
	stats["total_certificates"] = totalCerts

	// Top countries (dashboard needs code+name, so use custom query)
	rows, err := api.db.Query(`
		SELECT country_code, country_name, COUNT(*) as count
		FROM hosts
		WHERE country_code IS NOT NULL
		GROUP BY country_code, country_name
		ORDER BY count DESC
		LIMIT 10`)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to query top countries")
	} else {
		var countries []gin.H
		for rows.Next() {
			var code, name string
			var count int
			if err := rows.Scan(&code, &name, &count); err != nil {
				continue
			}
			countries = append(countries, gin.H{
				"code": code, "name": name, "count": count,
			})
		}
		if err := rows.Err(); err != nil {
			log.Warn().Err(err).Msg("Error iterating top countries rows")
		}
		rows.Close()
		stats["top_countries"] = countries
	}

	// Top services
	stats["top_services"] = api.queryValueCounts(`
		SELECT service, COUNT(*) as count
		FROM services
		WHERE service IS NOT NULL
		GROUP BY service
		ORDER BY count DESC
		LIMIT 10`, "service")

	// Cloud providers
	stats["cloud_providers"] = api.queryValueCounts(`
		SELECT cloud_provider, COUNT(*) as count
		FROM hosts
		WHERE cloud_provider IS NOT NULL
		GROUP BY cloud_provider
		ORDER BY count DESC`, "provider")

	c.JSON(200, stats)
}

// getCountryStats gets statistics by country
func (api *API) getCountryStats(c *gin.Context) {
	rows, err := api.db.Query(`
		SELECT country_code, country_name, COUNT(*) as host_count,
		       SUM(CASE WHEN cloud_provider IS NOT NULL THEN 1 ELSE 0 END) as cloud_count
		FROM hosts
		WHERE country_code IS NOT NULL
		GROUP BY country_code, country_name
		ORDER BY host_count DESC`)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var countries []gin.H
	for rows.Next() {
		var code, name string
		var hostCount, cloudCount int
		if err := rows.Scan(&code, &name, &hostCount, &cloudCount); err != nil {
			continue
		}

		countries = append(countries, gin.H{
			"code":        code,
			"name":        name,
			"host_count":  hostCount,
			"cloud_count": cloudCount,
		})
	}
	if err := rows.Err(); err != nil {
		log.Warn().Err(err).Msg("Error iterating country stats rows")
	}

	c.JSON(200, gin.H{"countries": countries})
}

// getServiceStats gets service statistics
func (api *API) getServiceStats(c *gin.Context) {
	rows, err := api.db.Query(`
		SELECT service, COUNT(*) as count,
		       COUNT(DISTINCT ip) as unique_hosts
		FROM services
		WHERE service IS NOT NULL
		GROUP BY service
		ORDER BY count DESC
		LIMIT 50`)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var services []gin.H
	for rows.Next() {
		var service string
		var count, uniqueHosts int
		if err := rows.Scan(&service, &count, &uniqueHosts); err != nil {
			continue
		}

		services = append(services, gin.H{
			"service":      service,
			"count":        count,
			"unique_hosts": uniqueHosts,
		})
	}
	if err := rows.Err(); err != nil {
		log.Warn().Err(err).Msg("Error iterating service stats rows")
	}

	c.JSON(200, gin.H{"services": services})
}

// getCloudStats gets cloud provider statistics
func (api *API) getCloudStats(c *gin.Context) {
	rows, err := api.db.Query(`
		SELECT cloud_provider, cloud_region, cloud_type, COUNT(*) as count
		FROM hosts
		WHERE cloud_provider IS NOT NULL
		GROUP BY cloud_provider, cloud_region, cloud_type
		ORDER BY count DESC`)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var clouds []gin.H
	for rows.Next() {
		var provider sql.NullString
		var region, cloudType sql.NullString
		var count int
		if err := rows.Scan(&provider, &region, &cloudType, &count); err != nil {
			continue
		}

		entry := gin.H{
			"provider": nullStr(provider),
			"count":    count,
		}
		setIfValid(entry, "region", region)
		setIfValid(entry, "cloud_type", cloudType)

		clouds = append(clouds, entry)
	}
	if err := rows.Err(); err != nil {
		log.Warn().Err(err).Msg("Error iterating cloud stats rows")
	}

	c.JSON(200, gin.H{"clouds": clouds})
}

// getTechnologyStats gets web technology statistics from http_data
func (api *API) getTechnologyStats(c *gin.Context) {
	rows, err := api.db.Query(`
		SELECT technologies
		FROM http_data
		WHERE technologies IS NOT NULL AND technologies != ''`)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	// Count technologies
	techCounts := make(map[string]int)
	for rows.Next() {
		var technologiesJSON string
		if err := rows.Scan(&technologiesJSON); err != nil {
			continue
		}

		// Parse JSON array of technology objects like [{"name":"Nginx","categories":["Reverse proxies"]}]
		var techArray []map[string]any
		if err := json.Unmarshal([]byte(technologiesJSON), &techArray); err == nil {
			for _, tech := range techArray {
				if name, ok := tech["name"].(string); ok && name != "" {
					techCounts[name]++
				}
			}
		}
	}
	if err := rows.Err(); err != nil {
		log.Warn().Err(err).Msg("Error iterating technology rows")
	}

	// Convert to sorted slice
	type techStat struct {
		Name  string
		Count int
	}
	var techStats []techStat
	for name, count := range techCounts {
		techStats = append(techStats, techStat{Name: name, Count: count})
	}

	// Sort by count descending
	sort.Slice(techStats, func(i, j int) bool {
		return techStats[i].Count > techStats[j].Count
	})

	// Take top 20
	if len(techStats) > 20 {
		techStats = techStats[:20]
	}

	// Convert to response format
	var technologies []gin.H
	for _, ts := range techStats {
		technologies = append(technologies, gin.H{
			"technology": ts.Name,
			"count":      ts.Count,
		})
	}

	c.JSON(200, gin.H{"technologies": technologies})
}

// getProductStats gets product statistics from services
func (api *API) getProductStats(c *gin.Context) {
	rows, err := api.db.Query(`
		SELECT product, COUNT(*) as count
		FROM services
		WHERE product IS NOT NULL AND product != ''
		GROUP BY product
		ORDER BY count DESC
		LIMIT 20`)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var products []gin.H
	for rows.Next() {
		var product string
		var count int
		if err := rows.Scan(&product, &count); err != nil {
			continue
		}

		products = append(products, gin.H{
			"product": product,
			"count":   count,
		})
	}
	if err := rows.Err(); err != nil {
		log.Warn().Err(err).Msg("Error iterating product stats rows")
	}

	c.JSON(200, gin.H{"products": products})
}

// getFacets returns available filter facets for dynamic filtering
func (api *API) getFacets(c *gin.Context) {
	facets := gin.H{}

	// Top countries
	facets["countries"] = api.queryValueCounts(`
		SELECT country_code, COUNT(*) as count
		FROM hosts
		WHERE country_code IS NOT NULL AND country_code != ''
		GROUP BY country_code
		ORDER BY count DESC
		LIMIT 20`, "value")

	// Top ports (int values, needs custom scan)
	rows, err := api.db.Query(`
		SELECT port, COUNT(*) as count
		FROM services
		GROUP BY port
		ORDER BY count DESC
		LIMIT 20`)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to query facet ports")
	} else {
		var ports []gin.H
		for rows.Next() {
			var port, count int
			if err := rows.Scan(&port, &count); err != nil {
				continue
			}
			ports = append(ports, gin.H{"value": port, "count": count})
		}
		if err := rows.Err(); err != nil {
			log.Warn().Err(err).Msg("Error iterating facet ports rows")
		}
		rows.Close()
		facets["ports"] = ports
	}

	// Top services
	facets["services"] = api.queryValueCounts(`
		SELECT service, COUNT(*) as count
		FROM services
		WHERE service IS NOT NULL
		GROUP BY service
		ORDER BY count DESC
		LIMIT 20`, "value")

	// Top ASNs (multi-column, needs custom scan)
	rows2, err := api.db.Query(`
		SELECT asn, as_org, COUNT(*) as count
		FROM hosts
		WHERE asn IS NOT NULL
		GROUP BY asn, as_org
		ORDER BY count DESC
		LIMIT 20`)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to query facet ASNs")
	} else {
		var asns []gin.H
		for rows2.Next() {
			var asn, count int
			var asOrg sql.NullString
			if err := rows2.Scan(&asn, &asOrg, &count); err != nil {
				continue
			}
			asns = append(asns, gin.H{"value": asn, "label": nullStr(asOrg), "count": count})
		}
		if err := rows2.Err(); err != nil {
			log.Warn().Err(err).Msg("Error iterating facet ASN rows")
		}
		rows2.Close()
		facets["asns"] = asns
	}

	// Cloud providers
	facets["cloud_providers"] = api.queryValueCounts(`
		SELECT cloud_provider, COUNT(*) as count
		FROM hosts
		WHERE cloud_provider IS NOT NULL AND cloud_provider != ''
		GROUP BY cloud_provider
		ORDER BY count DESC`, "value")

	// Cloud types (cdn, cloud, waf)
	facets["cloud_types"] = api.queryValueCounts(`
		SELECT cloud_type, COUNT(*) as count
		FROM hosts
		WHERE cloud_type IS NOT NULL AND cloud_type != ''
		GROUP BY cloud_type
		ORDER BY count DESC`, "value")

	c.JSON(200, facets)
}
