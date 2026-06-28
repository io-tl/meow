package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/mark3labs/mcp-go/mcp"
)

// ---------------------------------------------------------------------------
// meow_scan — Submit a scan request via NATS
// ---------------------------------------------------------------------------

func (h *mcpHandler) handleScan(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	target, err := req.RequireString("target")
	if err != nil {
		return mcp.NewToolResultError("target parameter required"), nil
	}

	if h.scanTracker == nil || !h.scanTracker.HasActiveScanners() {
		return mcp.NewToolResultError("no active scanners available — ensure at least one synscan instance is running in daemon mode"), nil
	}

	scanReq := ScanRequest{
		RequestID: uuid.New().String(),
		Target:    target,
		Ports:     req.GetString("ports", ""),
		RateLimit: req.GetInt("rate", 0),
		Timestamp: time.Now().Unix(),
	}

	data, err := json.Marshal(scanReq)
	if err != nil {
		return nil, fmt.Errorf("json marshal failed: %w", err)
	}

	if err := h.nc.Publish(TopicScanRequest, data); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to publish scan request: %v", err)), nil
	}

	return mcpEnvelope("meow_scan", []map[string]any{{
		"request_id": scanReq.RequestID,
		"message":    "scan request submitted",
		"target":     target,
		"ports":      scanReq.Ports,
	}}, false)
}
