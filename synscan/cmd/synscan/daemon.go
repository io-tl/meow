package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	natspub "meow/synscan/internal/nats"
	"meow/synscan/internal/scanner"
	"meow/synscan/pkg/types"

	"github.com/nats-io/nats.go"
)

func runDaemon(ctx context.Context, config *YAMLConfig, verbose bool) error {
	if config.NATS.URL == "" {
		config.NATS.URL = "nats://127.0.0.1:4222"
	}

	pub, err := natspub.NewPublisher(
		config.NATS.URL,
		config.NATS.Auth.Token,
		"", "",
		"daemon",
	)
	if err != nil {
		return fmt.Errorf("failed to connect to NATS: %w", err)
	}
	defer pub.Close()

	nodeID := natspub.PeerName()
	hostname, _ := os.Hostname()
	startTime := time.Now()

	fmt.Fprintln(os.Stderr, strings.Repeat("=", 60))
	fmt.Fprintln(os.Stderr, "SynScan Daemon Mode")
	fmt.Fprintln(os.Stderr, strings.Repeat("=", 60))
	fmt.Fprintf(os.Stderr, "Node ID:    %s\n", nodeID)
	fmt.Fprintf(os.Stderr, "NATS:       %s\n", config.NATS.URL)
	fmt.Fprintln(os.Stderr, "Waiting for scan requests on scan.request...")
	fmt.Fprintln(os.Stderr, strings.Repeat("=", 60))

	// Track current scan state for heartbeats
	var mu sync.Mutex
	currentStatus := "idle"
	currentScanID := ""
	currentTransport := ""

	// Heartbeat goroutine
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		// Send initial heartbeat immediately
		sendHeartbeat(pub, nodeID, hostname, currentStatus, currentScanID, currentTransport, startTime)

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				mu.Lock()
				status := currentStatus
				scanID := currentScanID
				transport := currentTransport
				mu.Unlock()
				sendHeartbeat(pub, nodeID, hostname, status, scanID, transport, startTime)
			}
		}
	}()

	// Subscribe to scan requests
	nc := pub.Conn()
	sub, err := nc.QueueSubscribe("scan.request", "synscan-workers", func(msg *nats.Msg) {
		var req types.ScanRequest
		if err := json.Unmarshal(msg.Data, &req); err != nil {
			log.Printf("Failed to unmarshal scan request: %v", err)
			return
		}

		log.Printf("Received scan request: %s (target=%s ports=%s)", req.RequestID, req.Target, req.Ports)

		mu.Lock()
		currentStatus = "scanning"
		currentScanID = req.RequestID
		mu.Unlock()

		transport := executeScanFromRequest(ctx, config, &req, pub, verbose)

		mu.Lock()
		currentStatus = "idle"
		currentScanID = ""
		currentTransport = transport
		mu.Unlock()

		log.Printf("Scan %s completed", req.RequestID)
	})
	if err != nil {
		return fmt.Errorf("failed to subscribe to scan.request: %w", err)
	}
	defer sub.Unsubscribe()

	<-ctx.Done()
	fmt.Fprintln(os.Stderr, "\nDaemon shutting down...")
	return nil
}

func sendHeartbeat(pub *natspub.Publisher, nodeID, hostname, status, scanID, transport string, startTime time.Time) {
	hb := &types.ScannerHeartbeat{
		NodeID:    nodeID,
		Hostname:  hostname,
		Status:    status,
		ScanID:    scanID,
		UptimeSec: int64(time.Since(startTime).Seconds()),
		Transport: transport,
		Timestamp: time.Now().Unix(),
	}
	if err := pub.PublishHeartbeat(hb); err != nil {
		log.Printf("Failed to publish heartbeat: %v", err)
	}
}

func executeScanFromRequest(ctx context.Context, config *YAMLConfig, req *types.ScanRequest, pub *natspub.Publisher, verbose bool) string {
	ports := req.Ports
	if ports == "" {
		ports = config.Synscan.Target.Ports
	}

	scanConfig, targetIPs, parsedPorts, err := prepareScanConfig(config, req.Target, ports, verbose)
	if err != nil {
		log.Printf("Scan %s: %v", req.RequestID, err)
		return ""
	}

	scanConfig.ScanID = req.RequestID
	scanConfig.Seed = time.Now().UnixNano()
	scanConfig.ResumeFrom = 0

	// Override rate limit if specified in request
	if req.RateLimit > 0 {
		scanConfig.RateLimit = req.RateLimit
	}

	scan, err := scanner.NewScanner(scanConfig)
	if err != nil {
		log.Printf("Scan %s: failed to create scanner: %v", req.RequestID, err)
		return ""
	}
	defer scan.Close()

	if verbose {
		log.Printf("Scan %s: starting (%d IPs, %d ports)", req.RequestID, len(targetIPs), len(parsedPorts))
	}

	results, err := scan.Scan(ctx)
	if err != nil {
		log.Printf("Scan %s: failed to start: %v", req.RequestID, err)
		return ""
	}

	processResults(results, pub, verbose)
	return scan.TransportMethod()
}
