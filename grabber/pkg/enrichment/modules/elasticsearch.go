package modules

import (
	"time"

	"meow/grabber/pkg/enrichment/modules/helpers"
)

// ElasticsearchModule implements the Elasticsearch enrichment module
type ElasticsearchModule struct {
	BaseModule
}

// ElasticsearchResult represents the enriched Elasticsearch data
type ElasticsearchResult struct {
	Protocol    string                 `json:"protocol"`
	Version     string                 `json:"version,omitempty"`
	ClusterName string                 `json:"cluster_name,omitempty"`
	Name        string                 `json:"name,omitempty"`
	Tagline     string                 `json:"tagline,omitempty"`
	Info        map[string]interface{} `json:"info,omitempty"`
	Error       string                 `json:"error,omitempty"`
}

func init() {
	Register(&ElasticsearchModule{
		BaseModule: NewBaseModule(
			"elasticsearch",
			[]string{"elastic"},
			true,
			10*time.Second,
		),
	})
}

func (m *ElasticsearchModule) Scan(ip string, port int) (interface{}, error) {
	return scanElasticsearch(ip, port, m.DefaultTimeout())
}

func scanElasticsearch(ip string, port int, timeout time.Duration) (*ElasticsearchResult, error) {
	result := &ElasticsearchResult{
		Protocol: "elasticsearch",
		Info:     make(map[string]interface{}),
	}

	data, err := helpers.HTTPProbeJSON(ip, port, "/", false, timeout)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	result.Info = data
	if name, ok := data["name"].(string); ok {
		result.Name = name
	}
	if clusterName, ok := data["cluster_name"].(string); ok {
		result.ClusterName = clusterName
	}
	if tagline, ok := data["tagline"].(string); ok {
		result.Tagline = tagline
	}
	if version, ok := data["version"].(map[string]interface{}); ok {
		if number, ok := version["number"].(string); ok {
			result.Version = number
		}
	}

	return result, nil
}
