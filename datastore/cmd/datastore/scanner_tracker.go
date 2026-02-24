package main

import (
	"sync"
	"time"
)

const scannerTimeout = 10 * time.Second

// ScannerNode represents a connected scanner instance
type ScannerNode struct {
	NodeID       string `json:"node_id"`
	Hostname     string `json:"hostname"`
	Status       string `json:"status"`
	ScanID       string `json:"scan_id,omitempty"`
	UptimeSec    int64  `json:"uptime_sec"`
	Transport    string `json:"transport,omitempty"`
	PacketsSent  int64  `json:"packets_sent,omitempty"`
	PacketsTotal int64  `json:"packets_total,omitempty"`
	LastSeen     int64  `json:"last_seen"`
}

// ScannerTracker tracks connected scanner nodes via heartbeats
type ScannerTracker struct {
	mu       sync.RWMutex
	scanners map[string]*ScannerNode
}

// NewScannerTracker creates a new tracker
func NewScannerTracker() *ScannerTracker {
	return &ScannerTracker{
		scanners: make(map[string]*ScannerNode),
	}
}

// UpdateHeartbeat updates or creates a scanner node entry
func (t *ScannerTracker) UpdateHeartbeat(hb *ScannerHeartbeat) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.scanners[hb.NodeID] = &ScannerNode{
		NodeID:       hb.NodeID,
		Hostname:     hb.Hostname,
		Status:       hb.Status,
		ScanID:       hb.ScanID,
		UptimeSec:    hb.UptimeSec,
		Transport:    hb.Transport,
		PacketsSent:  hb.PacketsSent,
		PacketsTotal: hb.PacketsTotal,
		LastSeen:     time.Now().Unix(),
	}
}

// GetActiveScanners returns scanners seen within the timeout window
// and cleans up stale entries to prevent memory leaks
func (t *ScannerTracker) GetActiveScanners() []*ScannerNode {
	t.mu.Lock()
	defer t.mu.Unlock()

	cutoff := time.Now().Add(-scannerTimeout).Unix()
	var active []*ScannerNode
	for id, node := range t.scanners {
		if node.LastSeen >= cutoff {
			active = append(active, node)
		} else {
			delete(t.scanners, id)
		}
	}
	return active
}

// HasActiveScanners returns true if at least one scanner is active
func (t *ScannerTracker) HasActiveScanners() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()

	cutoff := time.Now().Add(-scannerTimeout).Unix()
	for _, node := range t.scanners {
		if node.LastSeen >= cutoff {
			return true
		}
	}
	return false
}
