package modules

import (
	"encoding/json"
	"time"

	"meow/grabber/pkg/enrichment/modules/helpers"
)

// InfluxDBModule implements the InfluxDB enrichment module
type InfluxDBModule struct {
	BaseModule
}

type InfluxDBResult struct {
	Protocol   string            `json:"protocol"`
	Version    string            `json:"version,omitempty"`
	BuildInfo  map[string]string `json:"build_info,omitempty"`
	Ping       bool              `json:"ping"`
	Databases  []string          `json:"databases,omitempty"`
	Users      []string          `json:"users,omitempty"`
	AuthNeeded bool              `json:"auth_needed"`
	Error      string            `json:"error,omitempty"`
}

func init() {
	Register(&InfluxDBModule{
		BaseModule: NewBaseModule("influxdb", []string{}, true, 10*time.Second),
	})
}

func (m *InfluxDBModule) Scan(ip string, port int) (interface{}, error) {
	result := &InfluxDBResult{
		Protocol:  "influxdb",
		BuildInfo: make(map[string]string),
	}
	timeout := m.DefaultTimeout()

	// Ping endpoint
	pingResult, err := helpers.HTTPProbe(ip, port, "/ping", false, timeout)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	result.Ping = pingResult.StatusCode == 204
	result.Version = pingResult.Headers.Get("X-Influxdb-Version")
	result.BuildInfo["build"] = pingResult.Headers.Get("X-Influxdb-Build")

	// Try to get databases (may require auth)
	dbResult, err := helpers.HTTPProbe(ip, port, "/query?q=SHOW+DATABASES", false, timeout)
	if err == nil {
		if dbResult.StatusCode == 200 {
			var queryResult map[string]interface{}
			if json.Unmarshal(dbResult.Body, &queryResult) == nil {
				result.Databases = extractInfluxValues(queryResult)
			}
		} else if dbResult.StatusCode == 401 {
			result.AuthNeeded = true
		}
	}

	// Try to get users (may require auth)
	userResult, err := helpers.HTTPProbe(ip, port, "/query?q=SHOW+USERS", false, timeout)
	if err == nil {
		if userResult.StatusCode == 200 {
			var queryResult map[string]interface{}
			if json.Unmarshal(userResult.Body, &queryResult) == nil {
				result.Users = extractInfluxValues(queryResult)
			}
		}
	}

	return result, nil
}

func extractInfluxValues(queryResult map[string]interface{}) []string {
	var values []string
	if results, ok := queryResult["results"].([]interface{}); ok && len(results) > 0 {
		if result0, ok := results[0].(map[string]interface{}); ok {
			if series, ok := result0["series"].([]interface{}); ok && len(series) > 0 {
				if s, ok := series[0].(map[string]interface{}); ok {
					if vals, ok := s["values"].([]interface{}); ok {
						for _, v := range vals {
							if row, ok := v.([]interface{}); ok && len(row) > 0 {
								if name, ok := row[0].(string); ok {
									values = append(values, name)
								}
							}
						}
					}
				}
			}
		}
	}
	return values
}
