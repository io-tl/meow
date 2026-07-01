package main

import (
	"context"
	"testing"
)

// MCP host export must use the canonical field names shared with the REST export
// (country_code / as_org / cloud_provider / open_ports_count), not the legacy
// short names (country / org / cloud / open_ports).
func TestMCPExportHostsFieldNames(t *testing.T) {
	h := setupTestMCP(t)

	result, err := h.handleExport(context.Background(), callTool(map[string]any{
		"type": "hosts",
	}))
	assertNoError(t, result, err)

	var host map[string]any
	for _, r := range envResults(t, result) {
		m, _ := r.(map[string]any)
		if m["ip"] == "10.0.0.1" {
			host = m
		}
	}
	if host == nil {
		t.Fatal("host 10.0.0.1 not found in export")
	}

	for _, k := range []string{"country_code", "as_org", "cloud_provider"} {
		if _, ok := host[k]; !ok {
			t.Errorf("MCP host export missing canonical field %q (got %v)", k, host)
		}
	}
	for _, legacy := range []string{"country", "org", "cloud", "open_ports"} {
		if _, ok := host[legacy]; ok {
			t.Errorf("MCP host export still emits legacy field %q", legacy)
		}
	}
	if host["country_code"] != "FR" {
		t.Errorf("expected country_code=FR, got %v", host["country_code"])
	}
}

// MCP must support the domains export type (parity with REST).
func TestMCPExportDomains(t *testing.T) {
	h := setupTestMCP(t)

	result, err := h.handleExport(context.Background(), callTool(map[string]any{
		"type": "domains",
	}))
	assertNoError(t, result, err)

	found := false
	for _, r := range envResults(t, result) {
		m, _ := r.(map[string]any)
		if m["domain"] == "example.com" {
			found = true
			if _, ok := m["ip_count"]; !ok {
				t.Error("domain export missing ip_count")
			}
		}
	}
	if !found {
		t.Errorf("example.com not found in MCP domains export")
	}
}
