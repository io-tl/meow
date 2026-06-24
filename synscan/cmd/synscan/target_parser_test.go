package main

import (
	"net"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// --- parseTarget ---

func TestParseTarget_SingleIP(t *testing.T) {
	ips, err := parseTarget("192.168.1.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ips) != 1 {
		t.Fatalf("expected 1 IP, got %d", len(ips))
	}
	if ips[0] != "192.168.1.1" {
		t.Errorf("expected 192.168.1.1, got %s", ips[0])
	}
}

func TestParseTarget_SingleIP_InvalidReturnsError(t *testing.T) {
	_, err := parseTarget("999.999.999.999")
	if err == nil {
		t.Error("expected error for invalid IP")
	}
}

func TestParseTarget_SingleIP_NotAnIP(t *testing.T) {
	_, err := parseTarget("notanip")
	if err == nil {
		t.Error("expected error for non-IP string")
	}
}

func TestParseTarget_CIDR24(t *testing.T) {
	ips, err := parseTarget("192.168.1.0/24")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// /24 = 256 IPs, minus network (.0) and broadcast (.255) = 254
	if len(ips) != 254 {
		t.Fatalf("expected 254 IPs, got %d", len(ips))
	}
	// First should be .1, last should be .254
	if ips[0] != "192.168.1.1" {
		t.Errorf("first IP: expected 192.168.1.1, got %s", ips[0])
	}
	if ips[len(ips)-1] != "192.168.1.254" {
		t.Errorf("last IP: expected 192.168.1.254, got %s", ips[len(ips)-1])
	}
}

func TestParseTarget_CIDR32(t *testing.T) {
	ips, err := parseTarget("10.0.0.1/32")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ips) != 1 {
		t.Fatalf("expected 1 IP, got %d", len(ips))
	}
	if ips[0] != "10.0.0.1" {
		t.Errorf("expected 10.0.0.1, got %s", ips[0])
	}
}

func TestParseTarget_CIDR31(t *testing.T) {
	ips, err := parseTarget("10.0.0.0/31")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// /31 = 2 IPs, RFC 3021: no network/broadcast skip
	if len(ips) != 2 {
		t.Fatalf("expected 2 IPs for /31, got %d", len(ips))
	}
}

func TestParseTarget_CIDR_InvalidMask(t *testing.T) {
	_, err := parseTarget("192.168.1.0/33")
	if err == nil {
		t.Error("expected error for mask > 32")
	}
}

func TestParseTarget_CIDR_NegativeMask(t *testing.T) {
	_, err := parseTarget("192.168.1.0/-1")
	if err == nil {
		t.Error("expected error for negative mask")
	}
}

func TestParseTarget_RangeLastOctet(t *testing.T) {
	ips, err := parseTarget("192.168.1.1-10")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ips) != 10 {
		t.Fatalf("expected 10 IPs, got %d", len(ips))
	}
	if ips[0] != "192.168.1.1" {
		t.Errorf("first IP: expected 192.168.1.1, got %s", ips[0])
	}
	if ips[9] != "192.168.1.10" {
		t.Errorf("last IP: expected 192.168.1.10, got %s", ips[9])
	}
}

func TestParseTarget_RangeThirdOctet(t *testing.T) {
	ips, err := parseTarget("192.168.1-3.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ips) != 3 {
		t.Fatalf("expected 3 IPs, got %d", len(ips))
	}
	expected := []string{"192.168.1.1", "192.168.2.1", "192.168.3.1"}
	for i, e := range expected {
		if ips[i] != e {
			t.Errorf("ip[%d]: expected %s, got %s", i, e, ips[i])
		}
	}
}

func TestParseTarget_MultipleRanges(t *testing.T) {
	ips, err := parseTarget("192.168.1-3.10-12")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 3 x 3 = 9
	if len(ips) != 9 {
		t.Fatalf("expected 9 IPs, got %d", len(ips))
	}
	// Verify specific IPs exist
	ipSet := make(map[string]bool)
	for _, ip := range ips {
		ipSet[ip] = true
	}
	expected := []string{
		"192.168.1.10", "192.168.1.11", "192.168.1.12",
		"192.168.2.10", "192.168.2.11", "192.168.2.12",
		"192.168.3.10", "192.168.3.11", "192.168.3.12",
	}
	for _, e := range expected {
		if !ipSet[e] {
			t.Errorf("missing expected IP: %s", e)
		}
	}
}

func TestParseTarget_CIDRWithRanges(t *testing.T) {
	ips, err := parseTarget("192.168.1-2.0/24")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 2 CIDRs x 254 IPs = 508
	if len(ips) != 508 {
		t.Fatalf("expected 508 IPs, got %d", len(ips))
	}
}

func TestParseTarget_RangeStartGreaterThanEnd(t *testing.T) {
	_, err := parseTarget("192.168.10-5.1")
	if err == nil {
		t.Error("expected error when range start > end")
	}
}

func TestParseTarget_RangeOctetOverflow(t *testing.T) {
	_, err := parseTarget("192.168.0-256.1")
	if err == nil {
		t.Error("expected error when octet > 255")
	}
}

func TestParseTarget_RangeNegativeOctet(t *testing.T) {
	// "-1" as a start would be parsed as range "", "1" which should error
	_, err := parseTarget("192.168.-1.1")
	if err == nil {
		t.Error("expected error for negative octet")
	}
}

func TestParseTarget_InvalidOctetCount(t *testing.T) {
	_, err := parseTarget("192.168.1")
	if err == nil {
		t.Error("expected error for 3-octet IP with range")
	}
}

func TestParseTarget_SingleOctetRange(t *testing.T) {
	ips, err := parseTarget("10.0.0.1-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ips) != 1 {
		t.Fatalf("expected 1 IP for range 1-1, got %d", len(ips))
	}
}

func TestParseTargetsFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "targets.txt")
	content := "# comment\n192.168.1.1\n\n192.168.1.2-3\n10.0.0.0/30 # inline comment\n192.168.1.1\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write target file: %v", err)
	}

	ips, err := parseTargetsFromFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := []string{
		"192.168.1.1",
		"192.168.1.2",
		"192.168.1.3",
		"10.0.0.1",
		"10.0.0.2",
	}
	if len(ips) != len(expected) {
		t.Fatalf("expected %d IPs, got %d (%v)", len(expected), len(ips), ips)
	}
	for i, want := range expected {
		if ips[i] != want {
			t.Errorf("ip[%d]: expected %s, got %s", i, want, ips[i])
		}
	}
}

func TestParseTargetsFromFile_InvalidLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "targets.txt")
	if err := os.WriteFile(path, []byte("192.168.1.1\nnope\n"), 0644); err != nil {
		t.Fatalf("failed to write target file: %v", err)
	}

	_, err := parseTargetsFromFile(path)
	if err == nil {
		t.Fatal("expected error for invalid target file line")
	}
}

func TestLoadTargets(t *testing.T) {
	ips, err := loadTargets("192.168.1.1", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ips) != 1 || ips[0] != "192.168.1.1" {
		t.Fatalf("unexpected loadTargets result: %v", ips)
	}
}

func TestLoadTargets_MutuallyExclusive(t *testing.T) {
	_, err := loadTargets("192.168.1.1", "targets.txt")
	if err == nil {
		t.Fatal("expected error when target and target file are both set")
	}
}

// --- parsePorts ---

func TestParsePorts_SinglePort(t *testing.T) {
	ports, err := parsePorts("80")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ports) != 1 || ports[0] != 80 {
		t.Errorf("expected [80], got %v", ports)
	}
}

func TestParsePorts_MultiplePorts(t *testing.T) {
	ports, err := parsePorts("80,443,22")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ports) != 3 {
		t.Fatalf("expected 3 ports, got %d", len(ports))
	}
	expected := []int{80, 443, 22}
	for i, e := range expected {
		if ports[i] != e {
			t.Errorf("port[%d]: expected %d, got %d", i, e, ports[i])
		}
	}
}

func TestParsePorts_Range(t *testing.T) {
	ports, err := parsePorts("1-100")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ports) != 100 {
		t.Fatalf("expected 100 ports, got %d", len(ports))
	}
	if ports[0] != 1 || ports[99] != 100 {
		t.Errorf("expected range 1-100, got first=%d last=%d", ports[0], ports[99])
	}
}

func TestParsePorts_Mixed(t *testing.T) {
	ports, err := parsePorts("22,80-82,443")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := []int{22, 80, 81, 82, 443}
	if len(ports) != len(expected) {
		t.Fatalf("expected %d ports, got %d", len(expected), len(ports))
	}
	for i, e := range expected {
		if ports[i] != e {
			t.Errorf("port[%d]: expected %d, got %d", i, e, ports[i])
		}
	}
}

func TestParsePorts_WithSpaces(t *testing.T) {
	ports, err := parsePorts(" 80 , 443 , 22 ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ports) != 3 {
		t.Fatalf("expected 3 ports, got %d", len(ports))
	}
}

func TestParsePorts_RangeWithSpaces(t *testing.T) {
	ports, err := parsePorts("80 - 82")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ports) != 3 {
		t.Fatalf("expected 3 ports, got %d", len(ports))
	}
}

func TestParsePorts_MaxPort(t *testing.T) {
	ports, err := parsePorts("65535")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ports) != 1 || ports[0] != 65535 {
		t.Errorf("expected [65535], got %v", ports)
	}
}

func TestParsePorts_PortZero(t *testing.T) {
	_, err := parsePorts("0")
	if err == nil {
		t.Error("expected error for port 0")
	}
}

func TestParsePorts_PortTooHigh(t *testing.T) {
	_, err := parsePorts("65536")
	if err == nil {
		t.Error("expected error for port > 65535")
	}
}

func TestParsePorts_RangeStartHigherThanEnd(t *testing.T) {
	_, err := parsePorts("100-50")
	if err == nil {
		t.Error("expected error when range start > end")
	}
}

func TestParsePorts_EmptyString(t *testing.T) {
	_, err := parsePorts("")
	if err == nil {
		t.Error("expected error for empty string")
	}
}

func TestParsePorts_InvalidPort(t *testing.T) {
	_, err := parsePorts("abc")
	if err == nil {
		t.Error("expected error for non-numeric port")
	}
}

func TestParsePorts_RangeWithInvalidStart(t *testing.T) {
	_, err := parsePorts("abc-100")
	if err == nil {
		t.Error("expected error for invalid range start")
	}
}

func TestParsePorts_RangeWithInvalidEnd(t *testing.T) {
	_, err := parsePorts("1-abc")
	if err == nil {
		t.Error("expected error for invalid range end")
	}
}

func TestParsePorts_TrailingComma(t *testing.T) {
	ports, err := parsePorts("80,443,")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ports) != 2 {
		t.Errorf("expected 2 ports, got %d", len(ports))
	}
}

func TestParsePorts_FullRange(t *testing.T) {
	ports, err := parsePorts("1-65535")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ports) != 65535 {
		t.Errorf("expected 65535 ports, got %d", len(ports))
	}
}

// --- parseOctetRange ---

func TestParseOctetRange_SingleValue(t *testing.T) {
	vals, err := parseOctetRange("42")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(vals) != 1 || vals[0] != 42 {
		t.Errorf("expected [42], got %v", vals)
	}
}

func TestParseOctetRange_Range(t *testing.T) {
	vals, err := parseOctetRange("10-15")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(vals) != 6 {
		t.Fatalf("expected 6 values, got %d", len(vals))
	}
	for i, expected := range []int{10, 11, 12, 13, 14, 15} {
		if vals[i] != expected {
			t.Errorf("vals[%d]: expected %d, got %d", i, expected, vals[i])
		}
	}
}

func TestParseOctetRange_FullRange(t *testing.T) {
	vals, err := parseOctetRange("0-255")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(vals) != 256 {
		t.Errorf("expected 256 values, got %d", len(vals))
	}
}

func TestParseOctetRange_Overflow(t *testing.T) {
	_, err := parseOctetRange("0-256")
	if err == nil {
		t.Error("expected error for octet > 255")
	}
}

func TestParseOctetRange_StartGreaterThanEnd(t *testing.T) {
	_, err := parseOctetRange("100-50")
	if err == nil {
		t.Error("expected error when start > end")
	}
}

func TestParseOctetRange_Negative(t *testing.T) {
	_, err := parseOctetRange("-5")
	if err == nil {
		t.Error("expected error for negative value")
	}
}

func TestParseOctetRange_InvalidValue(t *testing.T) {
	_, err := parseOctetRange("abc")
	if err == nil {
		t.Error("expected error for non-numeric value")
	}
}

// --- expandCIDR ---

func TestExpandCIDR_24(t *testing.T) {
	_, ipnet, _ := net.ParseCIDR("10.0.0.0/24")
	ips := expandCIDR(ipnet)
	// /24 = 256 - 2 (net + broadcast) = 254
	if len(ips) != 254 {
		t.Fatalf("expected 254 IPs for /24, got %d", len(ips))
	}
	if ips[0] != "10.0.0.1" {
		t.Errorf("first IP: expected 10.0.0.1, got %s", ips[0])
	}
	if ips[253] != "10.0.0.254" {
		t.Errorf("last IP: expected 10.0.0.254, got %s", ips[253])
	}
}

func TestExpandCIDR_32(t *testing.T) {
	_, ipnet, _ := net.ParseCIDR("10.0.0.5/32")
	ips := expandCIDR(ipnet)
	if len(ips) != 1 {
		t.Fatalf("expected 1 IP for /32, got %d", len(ips))
	}
}

func TestExpandCIDR_30(t *testing.T) {
	_, ipnet, _ := net.ParseCIDR("10.0.0.0/30")
	ips := expandCIDR(ipnet)
	// /30 = 4 - 2 = 2 usable
	if len(ips) != 2 {
		t.Fatalf("expected 2 IPs for /30, got %d", len(ips))
	}
}

func TestExpandCIDR_28(t *testing.T) {
	_, ipnet, _ := net.ParseCIDR("10.0.0.0/28")
	ips := expandCIDR(ipnet)
	// /28 = 16 - 2 = 14 usable
	if len(ips) != 14 {
		t.Fatalf("expected 14 IPs for /28, got %d", len(ips))
	}
}

// --- Integration tests ---

func TestParseTarget_LargeRange_CountOnly(t *testing.T) {
	ips, err := parseTarget("10.0.0-3.0/24")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 4 subnets x 254 = 1016
	if len(ips) != 1016 {
		t.Errorf("expected 1016 IPs, got %d", len(ips))
	}
}

func TestParseTarget_AllIPsAreValid(t *testing.T) {
	ips, err := parseTarget("192.168.1-2.100-105")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			t.Errorf("generated invalid IP: %s", ipStr)
		}
	}
}

func TestParseTarget_NoDuplicates(t *testing.T) {
	ips, err := parseTarget("192.168.1-3.1-5")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	seen := make(map[string]bool)
	for _, ip := range ips {
		if seen[ip] {
			t.Errorf("duplicate IP: %s", ip)
		}
		seen[ip] = true
	}
}

func TestParsePorts_NoDuplicatesInRange(t *testing.T) {
	ports, err := parsePorts("1-100")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	seen := make(map[int]bool)
	for _, p := range ports {
		if seen[p] {
			t.Errorf("duplicate port: %d", p)
		}
		seen[p] = true
	}
}

func TestParsePorts_Sorted(t *testing.T) {
	ports, err := parsePorts("1-100")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !sort.IntsAreSorted(ports) {
		t.Error("ports from range should be sorted")
	}
}

// --- Edge cases for better coverage ---

func TestParseTarget_CIDR_DoubleSlash(t *testing.T) {
	_, err := parseTarget("10.0.0.0/24/16")
	if err == nil {
		t.Error("expected error for double slash in CIDR")
	}
}

func TestParseTarget_CIDR_InvalidIP(t *testing.T) {
	_, err := parseTarget("999.0.0.0/24")
	if err == nil {
		t.Error("expected error for invalid IP in CIDR")
	}
}

func TestParsePorts_RangeStartZero(t *testing.T) {
	_, err := parsePorts("0-100")
	if err == nil {
		t.Error("expected error for port range starting at 0")
	}
}

func TestParsePorts_RangeEndTooHigh(t *testing.T) {
	_, err := parsePorts("1-65536")
	if err == nil {
		t.Error("expected error for port range ending > 65535")
	}
}

func TestParseIPWithRanges_TooLarge(t *testing.T) {
	// 256 x 256 x 256 x 256 = 4B+ IPs > 16M limit
	_, err := parseTarget("0-255.0-255.0-255.0-255")
	if err == nil {
		t.Error("expected error for range exceeding 16M IPs")
	}
}

func TestParseCIDRWithRanges_InvalidCIDRInExpanded(t *testing.T) {
	// Range that produces invalid CIDR after expansion
	_, err := parseTarget("999.0.0.0-1/24")
	if err == nil {
		t.Error("expected error for invalid expanded CIDR")
	}
}

func TestParseOctetRange_MultiDash(t *testing.T) {
	_, err := parseOctetRange("1-2-3")
	if err == nil {
		t.Error("expected error for multiple dashes in octet range")
	}
}

func TestParsePorts_MultiDashInRange(t *testing.T) {
	_, err := parsePorts("1-2-3")
	if err == nil {
		t.Error("expected error for multi-dash in port range")
	}
}
