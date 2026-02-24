package main

import (
	"database/sql"
	"strconv"

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
		SELECT json_extract(value, '$.name') as tech_name, COUNT(*) as cnt
		FROM http_data, json_each(technologies)
		WHERE technologies IS NOT NULL AND technologies != ''
		  AND tech_name IS NOT NULL AND tech_name != ''
		GROUP BY tech_name
		ORDER BY cnt DESC
		LIMIT 20`)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var technologies []gin.H
	for rows.Next() {
		var name string
		var count int
		if err := rows.Scan(&name, &count); err != nil {
			continue
		}
		technologies = append(technologies, gin.H{
			"technology": name,
			"count":      count,
		})
	}
	if err := rows.Err(); err != nil {
		log.Warn().Err(err).Msg("Error iterating technology rows")
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

// getFacets returns available filter facets for dynamic filtering.
// Combines host-table and services-table facets into fewer queries to reduce DB round-trips.
func (api *API) getFacets(c *gin.Context) {
	facets := gin.H{}

	// === Query 1: All host-table facets in one pass using UNION ALL ===
	// Each sub-select is wrapped in a subquery so ORDER BY/LIMIT apply per-facet.
	rows, err := api.db.Query(`
		SELECT * FROM (
			SELECT 'country' as facet, country_code as value, '' as label, COUNT(*) as count
			FROM hosts WHERE country_code IS NOT NULL AND country_code != ''
			GROUP BY country_code ORDER BY count DESC LIMIT 20
		)
		UNION ALL
		SELECT * FROM (
			SELECT 'cloud_provider', cloud_provider, '', COUNT(*)
			FROM hosts WHERE cloud_provider IS NOT NULL AND cloud_provider != ''
			GROUP BY cloud_provider ORDER BY COUNT(*) DESC
		)
		UNION ALL
		SELECT * FROM (
			SELECT 'cloud_type', cloud_type, '', COUNT(*)
			FROM hosts WHERE cloud_type IS NOT NULL AND cloud_type != ''
			GROUP BY cloud_type ORDER BY COUNT(*) DESC
		)
		UNION ALL
		SELECT * FROM (
			SELECT 'asn', CAST(asn AS TEXT), COALESCE(as_org, ''), COUNT(*)
			FROM hosts WHERE asn IS NOT NULL
			GROUP BY asn, as_org ORDER BY COUNT(*) DESC LIMIT 20
		)`)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to query host facets")
	} else {
		countries := []gin.H{}
		cloudProviders := []gin.H{}
		cloudTypes := []gin.H{}
		asns := []gin.H{}

		for rows.Next() {
			var facet, value, label string
			var count int
			if err := rows.Scan(&facet, &value, &label, &count); err != nil {
				continue
			}
			switch facet {
			case "country":
				countries = append(countries, gin.H{"value": value, "count": count})
			case "cloud_provider":
				cloudProviders = append(cloudProviders, gin.H{"value": value, "count": count})
			case "cloud_type":
				cloudTypes = append(cloudTypes, gin.H{"value": value, "count": count})
			case "asn":
				entry := gin.H{"value": value, "count": count}
				if label != "" {
					entry["label"] = label
				}
				asns = append(asns, entry)
			}
		}
		if err := rows.Err(); err != nil {
			log.Warn().Err(err).Msg("Error iterating host facets rows")
		}
		rows.Close()

		facets["countries"] = countries
		facets["cloud_providers"] = cloudProviders
		facets["cloud_types"] = cloudTypes
		facets["asns"] = asns
	}

	// === Query 2: All services-table facets in one pass ===
	rows2, err := api.db.Query(`
		SELECT * FROM (
			SELECT 'port' as facet, CAST(port AS TEXT) as value, COUNT(*) as count
			FROM services GROUP BY port ORDER BY count DESC LIMIT 20
		)
		UNION ALL
		SELECT * FROM (
			SELECT 'service', service, COUNT(*)
			FROM services WHERE service IS NOT NULL
			GROUP BY service ORDER BY COUNT(*) DESC LIMIT 20
		)`)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to query services facets")
	} else {
		ports := []gin.H{}
		services := []gin.H{}

		for rows2.Next() {
			var facet, value string
			var count int
			if err := rows2.Scan(&facet, &value, &count); err != nil {
				continue
			}
			switch facet {
			case "port":
				// Convert back to int for API compatibility
				if p, err := strconv.Atoi(value); err == nil {
					ports = append(ports, gin.H{"value": p, "count": count})
				}
			case "service":
				services = append(services, gin.H{"value": value, "count": count})
			}
		}
		if err := rows2.Err(); err != nil {
			log.Warn().Err(err).Msg("Error iterating services facets rows")
		}
		rows2.Close()

		facets["ports"] = ports
		facets["services"] = services
	}

	c.JSON(200, facets)
}
