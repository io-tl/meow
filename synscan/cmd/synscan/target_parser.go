package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

func loadTargets(target, targetFile string) ([]string, error) {
	switch {
	case target != "" && targetFile != "":
		return nil, fmt.Errorf("target and target file are mutually exclusive")
	case targetFile != "":
		return parseTargetsFromFile(targetFile)
	case target != "":
		return parseTarget(target)
	default:
		return nil, fmt.Errorf("no target specified")
	}
}

// parseTarget parses various nmap-style target formats and returns a list of IPs
// Supported formats:
//   - 192.168.0.1                    (single IP)
//   - 192.168.0.0/24                 (CIDR)
//   - 192.168.1-244.1                (range in one octet)
//   - 192.168.0.1-166                (range in last octet)
//   - 192.168-170.1-66.1-77          (multiple ranges)
//   - 192.168.0-16.0/24              (CIDR with range)
func parseTarget(target string) ([]string, error) {
	// Check if it's a CIDR notation (possibly with ranges)
	if strings.Contains(target, "/") {
		return parseCIDRWithRanges(target)
	}

	// Check if it contains any ranges
	if strings.Contains(target, "-") {
		return parseIPWithRanges(target)
	}

	// Single IP
	ip := net.ParseIP(target)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", target)
	}
	return []string{ip.String()}, nil
}

func parseTargetsFromFile(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open target file: %w", err)
	}
	defer file.Close()

	var targets []string
	seen := make(map[string]struct{})
	scanner := bufio.NewScanner(file)

	for lineNo := 1; scanner.Scan(); lineNo++ {
		line := strings.TrimSpace(scanner.Text())
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if line == "" {
			continue
		}

		ips, err := parseTarget(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNo, err)
		}

		for _, ip := range ips {
			if _, exists := seen[ip]; exists {
				continue
			}
			seen[ip] = struct{}{}
			targets = append(targets, ip)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read target file: %w", err)
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("target file is empty")
	}

	return targets, nil
}

// parseCIDRWithRanges handles CIDR notation with optional ranges in octets
// Example: 192.168.0-16.0/24
func parseCIDRWithRanges(target string) ([]string, error) {
	parts := strings.Split(target, "/")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid CIDR format: %s", target)
	}

	maskStr := parts[1]
	mask, err := strconv.Atoi(maskStr)
	if err != nil || mask < 0 || mask > 32 {
		return nil, fmt.Errorf("invalid CIDR mask: %s", maskStr)
	}

	// If the IP part contains ranges, expand them first
	var baseIPs []string
	if strings.Contains(parts[0], "-") {
		baseIPs, err = parseIPWithRanges(parts[0])
		if err != nil {
			return nil, err
		}
	} else {
		baseIPs = []string{parts[0]}
	}

	// For each base IP, expand the CIDR
	var allIPs []string
	for _, baseIP := range baseIPs {
		cidr := baseIP + "/" + maskStr
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR: %s", cidr)
		}
		ips := expandCIDR(ipnet)
		allIPs = append(allIPs, ips...)
	}

	return allIPs, nil
}

// parseIPWithRanges handles IP addresses with ranges in octets
// Examples:
//   - 192.168.1-244.1           (range in third octet)
//   - 192.168.0.1-166           (range in fourth octet)
//   - 192.168-170.1-66.1-77     (multiple ranges)
func parseIPWithRanges(target string) ([]string, error) {
	octets := strings.Split(target, ".")
	if len(octets) != 4 {
		return nil, fmt.Errorf("invalid IP format: %s", target)
	}

	// Parse each octet and get the range
	var octetRanges [4][]int
	for i, octet := range octets {
		ranges, err := parseOctetRange(octet)
		if err != nil {
			return nil, fmt.Errorf("invalid octet '%s': %v", octet, err)
		}
		octetRanges[i] = ranges
	}

	// Check total IP count before allocation
	totalIPs := len(octetRanges[0]) * len(octetRanges[1]) * len(octetRanges[2]) * len(octetRanges[3])
	const maxIPs = 1 << 24 // 16M IPs (a /8)
	if totalIPs > maxIPs {
		return nil, fmt.Errorf("target range too large: %d IPs (max %d)", totalIPs, maxIPs)
	}

	// Generate all combinations
	ips := make([]string, 0, totalIPs)
	for _, o1 := range octetRanges[0] {
		for _, o2 := range octetRanges[1] {
			for _, o3 := range octetRanges[2] {
				for _, o4 := range octetRanges[3] {
					ip := fmt.Sprintf("%d.%d.%d.%d", o1, o2, o3, o4)
					ips = append(ips, ip)
				}
			}
		}
	}

	return ips, nil
}

// parseOctetRange parses an octet which can be a single number or a range
// Examples: "1", "1-244", "168-170"
func parseOctetRange(octet string) ([]int, error) {
	// Check if it's a range
	if strings.Contains(octet, "-") {
		parts := strings.Split(octet, "-")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid range format: %s", octet)
		}

		start, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil {
			return nil, fmt.Errorf("invalid start value: %s", parts[0])
		}

		end, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil {
			return nil, fmt.Errorf("invalid end value: %s", parts[1])
		}

		if start < 0 || start > 255 || end < 0 || end > 255 {
			return nil, fmt.Errorf("octet values must be 0-255: %d-%d", start, end)
		}

		if start > end {
			return nil, fmt.Errorf("range start must be <= end: %d-%d", start, end)
		}

		var values []int
		for i := start; i <= end; i++ {
			values = append(values, i)
		}
		return values, nil
	}

	// Single value
	val, err := strconv.Atoi(strings.TrimSpace(octet))
	if err != nil {
		return nil, fmt.Errorf("invalid octet value: %s", octet)
	}

	if val < 0 || val > 255 {
		return nil, fmt.Errorf("octet value must be 0-255: %d", val)
	}

	return []int{val}, nil
}

// expandCIDR expands a CIDR into individual IPs
func expandCIDR(ipnet *net.IPNet) []string {
	var ips []string

	// Get the first IP in the range
	ip := make(net.IP, len(ipnet.IP))
	copy(ip, ipnet.IP)

	// Iterate through all IPs in the CIDR
	for ipnet.Contains(ip) {
		ips = append(ips, ip.String())
		incIP(ip)
	}

	// Remove network and broadcast addresses for /24 and smaller
	ones, bits := ipnet.Mask.Size()
	if ones < bits && len(ips) > 2 {
		// Remove first (network) and last (broadcast) addresses
		return ips[1 : len(ips)-1]
	}

	return ips
}

// incIP increments an IP address
func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// parsePorts parses a port specification string (e.g. "80,443,8000-8100")
func parsePorts(s string) ([]int, error) {
	var ports []int

	parts := strings.Split(s, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// Check if it's a range
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("invalid port range: %s", part)
			}

			start, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid port: %s", rangeParts[0])
			}

			end, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid port: %s", rangeParts[1])
			}

			if start < 1 || start > 65535 {
				return nil, fmt.Errorf("port out of range (1-65535): %d", start)
			}
			if end < 1 || end > 65535 {
				return nil, fmt.Errorf("port out of range (1-65535): %d", end)
			}
			if start > end {
				return nil, fmt.Errorf("invalid port range: start %d > end %d", start, end)
			}

			for p := start; p <= end; p++ {
				ports = append(ports, p)
			}
		} else {
			port, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid port: %s", part)
			}
			if port < 1 || port > 65535 {
				return nil, fmt.Errorf("port out of range (1-65535): %d", port)
			}
			ports = append(ports, port)
		}
	}

	if len(ports) == 0 {
		return nil, fmt.Errorf("no valid ports specified")
	}

	return ports, nil
}
