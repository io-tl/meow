package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"meow/synscan/internal/nats"
	"meow/synscan/internal/packet"
	"meow/synscan/internal/scanner"
	"meow/synscan/pkg/types"

	"github.com/google/uuid"
)

func encodeScanToken(seed int64, offset int) string {
	return fmt.Sprintf("%016x%08x", uint64(seed), uint32(offset))
}

func decodeScanToken(token string) (int64, int, error) {
	if len(token) != 24 {
		return 0, 0, fmt.Errorf("invalid token length: expected 24 hex chars, got %d", len(token))
	}
	seedVal, err := strconv.ParseUint(token[:16], 16, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid seed in token: %w", err)
	}
	offsetVal, err := strconv.ParseUint(token[16:], 16, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid offset in token: %w", err)
	}
	return int64(seedVal), int(offsetVal), nil
}

// prepareScanConfig parses targets and ports, resolves source IP, and builds a ScanConfig.
// Used by both run() and executeScanFromRequest() to avoid duplication.
func prepareScanConfig(config *YAMLConfig, target, ports string, verbose bool) (*types.ScanConfig, []string, []int, error) {
	targetIPs, err := parseTarget(target)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("invalid target: %w", err)
	}

	if len(targetIPs) == 0 {
		return nil, nil, nil, fmt.Errorf("no valid IPs found in target")
	}

	if verbose {
		log.Printf("Target parsed: %d IPs", len(targetIPs))
	}

	if len(targetIPs) > 100000 {
		log.Printf("WARNING: Large scan (%d IPs) - this may take a while", len(targetIPs))
	}

	parsedPorts, err := parsePorts(ports)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("invalid ports: %w", err)
	}

	sourceIP, err := resolveSourceIP(config, targetIPs[0], verbose)
	if err != nil {
		return nil, nil, nil, err
	}

	scanConfig := buildScanConfig(config, targetIPs, parsedPorts, sourceIP)
	return scanConfig, targetIPs, parsedPorts, nil
}

func run(ctx context.Context, config *YAMLConfig, verbose bool, resumeToken string) error {
	scanConfig, _, ports, err := prepareScanConfig(config, config.Synscan.Target.CIDR, config.Synscan.Target.Ports, verbose)
	if err != nil {
		return err
	}

	// Handle seed and resume
	var seed int64
	var resumeFrom int
	if resumeToken != "" {
		seed, resumeFrom, err = decodeScanToken(resumeToken)
		if err != nil {
			return fmt.Errorf("invalid resume token: %w", err)
		}
	} else {
		seed = time.Now().UnixNano()
		resumeFrom = 0
	}
	scanConfig.Seed = seed
	scanConfig.ResumeFrom = resumeFrom

	scan, err := scanner.NewScanner(scanConfig)
	if err != nil {
		return fmt.Errorf("failed to create scanner: %w", err)
	}
	defer scan.Close()

	pub := setupNATSPublisher(scanConfig, verbose)
	if pub != nil {
		defer pub.Close()
	}

	printConfigSummary(config, len(ports), pub != nil)
	if resumeFrom > 0 {
		fmt.Fprintf(os.Stderr, "Resuming from packet %d\n", resumeFrom)
		fmt.Fprintln(os.Stderr, strings.Repeat("=", 60))
	}

	results, err := scan.Scan(ctx)
	if err != nil {
		return fmt.Errorf("failed to start scan: %w", err)
	}

	stats := processResults(results, pub, verbose)

	printScanSummary(stats.duration, stats.open, stats.closed, stats.filtered)

	if ctx.Err() != nil {
		done, total := scan.Progress()
		if done > 0 {
			resumeAt := resumeFrom + done
			token := encodeScanToken(seed, resumeAt)
			fmt.Fprintf(os.Stderr, "Interrupted at packet %d/%d\n", resumeAt, total)
			fmt.Fprintf(os.Stderr, "To resume: synscan [same flags] --resume %s\n", token)
		}
	}

	return nil
}

type scanStats struct {
	open     int
	closed   int
	filtered int
	duration time.Duration
}

func processResults(results <-chan *types.ScanResult, pub *nats.Publisher, verbose bool) scanStats {
	var stats scanStats
	startTime := time.Now()

	for result := range results {
		switch result.State {
		case types.PortOpen:
			stats.open++
			fmt.Printf("%s:%d\n", result.IP, result.Port)

			if pub != nil {
				if err := pub.PublishResult(result); err != nil {
					log.Printf("Failed to publish result: %v", err)
				}
			}

		case types.PortClosed:
			stats.closed++
			if verbose {
				fmt.Fprintf(os.Stderr, "[-] %s:%d CLOSED\n", result.IP, result.Port)
			}

		case types.PortFiltered:
			stats.filtered++
			if verbose {
				fmt.Fprintf(os.Stderr, "[?] %s:%d FILTERED\n", result.IP, result.Port)
			}
		}
	}

	stats.duration = time.Since(startTime)
	return stats
}

func resolveSourceIP(config *YAMLConfig, targetHint string, verbose bool) (net.IP, error) {
	if config.Synscan.Network.Interface != "" {
		ip, err := packet.GetInterfaceIP(config.Synscan.Network.Interface)
		if err != nil {
			return nil, fmt.Errorf("failed to get interface IP: %w", err)
		}
		if verbose {
			log.Printf("Using source IP from interface %s: %s", config.Synscan.Network.Interface, ip)
		}
		return ip, nil
	}

	ip := getRoutedIP(targetHint)
	if ip == nil {
		ip = getDefaultIP()
	}
	if ip == nil {
		return nil, fmt.Errorf("could not detect source IP, please specify --interface")
	}
	if verbose {
		log.Printf("Auto-detected source IP: %s", ip)
	}
	return ip, nil
}

func buildScanConfig(config *YAMLConfig, targetIPs []string, ports []int, sourceIP net.IP) *types.ScanConfig {
	return &types.ScanConfig{
		Interface:           config.Synscan.Network.Interface,
		SourceIP:            sourceIP,
		SourcePort:          40000, // Initial port (randomizer will handle range)
		TargetIPs:           targetIPs,
		Ports:               ports,
		RateLimit:           config.Synscan.Performance.RateLimit,
		TimeoutMS:           config.Synscan.Performance.TimeoutMS,
		SendBatch:           config.Synscan.Performance.Batch.Send,
		RecvBatch:           config.Synscan.Performance.Batch.Recv,
		RingSize:            config.Synscan.Performance.Batch.RingSize,
		IPBatchSize:         uint32(config.Synscan.Performance.Batch.IPBatchSize),
		NATSUrl:             config.NATS.URL,
		NATSToken:           config.NATS.Auth.Token,
		RandomizeIPs:        true,
		RandomizePorts:      true,
		RandomizeSourcePort: true,
		SourcePortMin:       30000,
		SourcePortMax:       60000,
		TimingJitter:        false, // Disabled by default
		JitterMaxMS:         0,
		ScanID:              uuid.New().String(),
	}
}

func setupNATSPublisher(scanConfig *types.ScanConfig, verbose bool) *nats.Publisher {
	if scanConfig.NATSUrl == "" {
		log.Printf("WARNING: NATS not configured - results will not be published")
		return nil
	}

	if verbose {
		log.Printf("Connecting to NATS: %s", scanConfig.NATSUrl)
	}

	pub, err := nats.NewPublisher(
		scanConfig.NATSUrl,
		scanConfig.NATSToken,
		scanConfig.NATSUser,
		scanConfig.NATSPassword,
		scanConfig.ScanID,
	)
	if err != nil {
		log.Printf("WARNING: NATS unavailable, results will not be published")
		return nil
	}

	if verbose {
		log.Printf("Connected to NATS successfully")
	}
	return pub
}

// getRoutedIP uses the OS routing table to find the source IP that would be used
// to reach the target. This picks the correct interface even with virtual adapters (WSL, VMware, etc).
func getRoutedIP(target string) net.IP {
	conn, err := net.Dial("udp4", target+":80")
	if err != nil {
		return nil
	}
	defer conn.Close()
	if localAddr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		return localAddr.IP.To4()
	}
	return nil
}

func getDefaultIP() net.IP {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.To4()
			}
		}
	}

	return nil
}

func printConfigSummary(config *YAMLConfig, numPorts int, natsConnected bool) {
	fmt.Fprintln(os.Stderr, strings.Repeat("=", 60))
	fmt.Fprintln(os.Stderr, "Scan Configuration")
	fmt.Fprintln(os.Stderr, strings.Repeat("=", 60))
	if config.Synscan.Target.TopPorts > 0 {
		fmt.Fprintf(os.Stderr, "Target:     %s (top %d ports)\n", config.Synscan.Target.CIDR, config.Synscan.Target.TopPorts)
	} else {
		fmt.Fprintf(os.Stderr, "Target:     %s (%d ports)\n", config.Synscan.Target.CIDR, numPorts)
	}
	if config.Synscan.Network.Interface != "" {
		fmt.Fprintf(os.Stderr, "Interface:  %s\n", config.Synscan.Network.Interface)
	}
	fmt.Fprintf(os.Stderr, "Rate:       %d pps\n", config.Synscan.Performance.RateLimit)
	fmt.Fprintf(os.Stderr, "Timeout:    %dms\n", config.Synscan.Performance.TimeoutMS)
	if natsConnected {
		fmt.Fprintf(os.Stderr, "NATS:       %s\n", config.NATS.URL)
	}
	fmt.Fprintln(os.Stderr, strings.Repeat("=", 60))
}

func printScanSummary(duration time.Duration, openPorts, closedPorts, filteredPorts int) {
	fmt.Fprintln(os.Stderr, "\n"+strings.Repeat("=", 60))
	fmt.Fprintln(os.Stderr, "Scan Summary")
	fmt.Fprintln(os.Stderr, strings.Repeat("=", 60))
	fmt.Fprintf(os.Stderr, "Duration:        %s\n", duration.Round(time.Second))
	fmt.Fprintf(os.Stderr, "Open Ports:      %d\n", openPorts)
	fmt.Fprintf(os.Stderr, "Closed Ports:    %d\n", closedPorts)
	fmt.Fprintf(os.Stderr, "Filtered Ports:  %d\n", filteredPorts)
	fmt.Fprintf(os.Stderr, "Total:           %d\n", openPorts+closedPorts+filteredPorts)
	fmt.Fprintln(os.Stderr, strings.Repeat("=", 60))
}
