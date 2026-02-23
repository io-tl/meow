package modules

import (
	"time"

	"meow/grabber/pkg/enrichment/modules/helpers"
)

// CouchDBModule implements the CouchDB enrichment module
type CouchDBModule struct {
	BaseModule
}

type CouchDBResult struct {
	Protocol string                 `json:"protocol"`
	Version  string                 `json:"version,omitempty"`
	Vendor   map[string]interface{} `json:"vendor,omitempty"`
	Error    string                 `json:"error,omitempty"`
}

func init() {
	Register(&CouchDBModule{
		BaseModule: NewBaseModule("couchdb", []string{}, true, 10*time.Second),
	})
}

func (m *CouchDBModule) Scan(ip string, port int) (interface{}, error) {
	result := &CouchDBResult{Protocol: "couchdb"}

	data, err := helpers.HTTPProbeJSON(ip, port, "/", false, m.DefaultTimeout())
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	if version, ok := data["version"].(string); ok {
		result.Version = version
	}
	if vendor, ok := data["vendor"].(map[string]interface{}); ok {
		result.Vendor = vendor
	}

	return result, nil
}
