package main

import (
	"bytes"
	"net"
	"os"
	"testing"
	"time"

	"meow/synscan/pkg/types"
)

// --- encodeScanToken / decodeScanToken ---

func TestEncodeScanToken_Format(t *testing.T) {
	token := encodeScanToken(0, 0)
	if len(token) != 24 {
		t.Fatalf("expected 24 chars, got %d: %s", len(token), token)
	}
	if token != "0000000000000000" + "00000000" {
		t.Errorf("expected all zeros, got %s", token)
	}
}

func TestEncodeScanToken_Length(t *testing.T) {
	tests := []struct {
		seed   int64
		offset int
	}{
		{0, 0},
		{1, 1},
		{12345678, 99999},
		{-1, 0},                // negative seed (wraps to uint64)
		{1<<62, 1<<31 - 1},    // large values
	}
	for _, tt := range tests {
		token := encodeScanToken(tt.seed, tt.offset)
		if len(token) != 24 {
			t.Errorf("seed=%d offset=%d: expected 24 chars, got %d", tt.seed, tt.offset, len(token))
		}
	}
}

func TestDecodeScanToken_Valid(t *testing.T) {
	token := encodeScanToken(42, 100)
	seed, offset, err := decodeScanToken(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if seed != 42 {
		t.Errorf("expected seed 42, got %d", seed)
	}
	if offset != 100 {
		t.Errorf("expected offset 100, got %d", offset)
	}
}

func TestScanToken_Roundtrip(t *testing.T) {
	tests := []struct {
		seed   int64
		offset int
	}{
		{0, 0},
		{1, 1},
		{1707123456789, 45678},
		{9999999999, 0},
		{0, 999999},
	}
	for _, tt := range tests {
		token := encodeScanToken(tt.seed, tt.offset)
		seed, offset, err := decodeScanToken(token)
		if err != nil {
			t.Errorf("seed=%d offset=%d: decode error: %v", tt.seed, tt.offset, err)
			continue
		}
		if seed != tt.seed {
			t.Errorf("seed roundtrip: expected %d, got %d", tt.seed, seed)
		}
		if offset != tt.offset {
			t.Errorf("offset roundtrip: expected %d, got %d", tt.offset, offset)
		}
	}
}

func TestDecodeScanToken_InvalidLength(t *testing.T) {
	tests := []string{
		"",
		"abc",
		"0000000000000000000000",   // 22 chars
		"000000000000000000000000000", // 27 chars
	}
	for _, token := range tests {
		_, _, err := decodeScanToken(token)
		if err == nil {
			t.Errorf("expected error for token %q (len=%d)", token, len(token))
		}
	}
}

func TestDecodeScanToken_InvalidHex(t *testing.T) {
	// Valid length (24) but invalid hex chars in seed portion
	_, _, err := decodeScanToken("GGGGGGGGGGGGGGGG00000000")
	if err == nil {
		t.Error("expected error for invalid hex in seed")
	}
}

func TestDecodeScanToken_InvalidHexOffset(t *testing.T) {
	// Valid seed hex, invalid offset hex
	_, _, err := decodeScanToken("0000000000000000GGGGGGGG")
	if err == nil {
		t.Error("expected error for invalid hex in offset")
	}
}

func TestScanToken_DifferentSeedsProduceDifferentTokens(t *testing.T) {
	t1 := encodeScanToken(1, 0)
	t2 := encodeScanToken(2, 0)
	if t1 == t2 {
		t.Error("different seeds should produce different tokens")
	}
}

func TestScanToken_DifferentOffsetsProduceDifferentTokens(t *testing.T) {
	t1 := encodeScanToken(42, 100)
	t2 := encodeScanToken(42, 200)
	if t1 == t2 {
		t.Error("different offsets should produce different tokens")
	}
}

func TestScanToken_SeedPartIs16Chars(t *testing.T) {
	token := encodeScanToken(255, 0)
	seedPart := token[:16]
	offsetPart := token[16:]
	if len(seedPart) != 16 {
		t.Errorf("seed part should be 16 chars, got %d", len(seedPart))
	}
	if len(offsetPart) != 8 {
		t.Errorf("offset part should be 8 chars, got %d", len(offsetPart))
	}
	if offsetPart != "00000000" {
		t.Errorf("offset should be 00000000, got %s", offsetPart)
	}
}

func TestScanToken_NegativeSeedRoundtrip(t *testing.T) {
	// Negative seed gets cast to uint64 then back
	token := encodeScanToken(-1, 50)
	seed, offset, err := decodeScanToken(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if seed != -1 {
		t.Errorf("expected seed -1, got %d", seed)
	}
	if offset != 50 {
		t.Errorf("expected offset 50, got %d", offset)
	}
}

func TestScanToken_MaxOffset(t *testing.T) {
	// Max uint32 offset
	maxOffset := int(^uint32(0)) // 4294967295
	token := encodeScanToken(1, maxOffset)
	_, offset, err := decodeScanToken(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if offset != maxOffset {
		t.Errorf("expected max offset %d, got %d", maxOffset, offset)
	}
}

// --- buildScanConfig ---

func TestBuildScanConfig_Basic(t *testing.T) {
	config := &YAMLConfig{
		NATS: NATSConfig{
			URL:  "nats://localhost:4222",
			Auth: NATSAuthConfig{Token: "secret"},
		},
		Synscan: SynscanConfig{
			Network: NetworkConfig{Interface: "eth0"},
			Performance: PerformanceConfig{
				RateLimit: 5000,
				TimeoutMS: 3000,
				Batch: BatchConfig{
					Send:        64,
					Recv:        64,
					RingSize:    4096,
					IPBatchSize: 4096,
				},
			},
		},
	}
	targetIPs := []string{"10.0.0.1", "10.0.0.2"}
	ports := []int{80, 443}
	sourceIP := net.ParseIP("192.168.1.100")

	sc := buildScanConfig(config, targetIPs, ports, sourceIP)

	if sc.Interface != "eth0" {
		t.Errorf("Interface: expected eth0, got %s", sc.Interface)
	}
	if !sc.SourceIP.Equal(sourceIP) {
		t.Errorf("SourceIP: expected %s, got %s", sourceIP, sc.SourceIP)
	}
	if sc.SourcePort != 40000 {
		t.Errorf("SourcePort: expected 40000, got %d", sc.SourcePort)
	}
	if len(sc.TargetIPs) != 2 {
		t.Errorf("TargetIPs: expected 2, got %d", len(sc.TargetIPs))
	}
	if len(sc.Ports) != 2 {
		t.Errorf("Ports: expected 2, got %d", len(sc.Ports))
	}
	if sc.RateLimit != 5000 {
		t.Errorf("RateLimit: expected 5000, got %d", sc.RateLimit)
	}
	if sc.TimeoutMS != 3000 {
		t.Errorf("TimeoutMS: expected 3000, got %d", sc.TimeoutMS)
	}
	if sc.NATSUrl != "nats://localhost:4222" {
		t.Errorf("NATSUrl: expected nats://localhost:4222, got %s", sc.NATSUrl)
	}
	if sc.NATSToken != "secret" {
		t.Errorf("NATSToken: expected secret, got %s", sc.NATSToken)
	}
}

func TestBuildScanConfig_HardcodedDefaults(t *testing.T) {
	config := &YAMLConfig{
		Synscan: SynscanConfig{
			Performance: PerformanceConfig{
				Batch: BatchConfig{
					Send:        64,
					Recv:        64,
					RingSize:    4096,
					IPBatchSize: 4096,
				},
			},
		},
	}
	sc := buildScanConfig(config, []string{"10.0.0.1"}, []int{80}, net.ParseIP("10.0.0.100"))

	if !sc.RandomizeIPs {
		t.Error("RandomizeIPs should be true")
	}
	if !sc.RandomizePorts {
		t.Error("RandomizePorts should be true")
	}
	if !sc.RandomizeSourcePort {
		t.Error("RandomizeSourcePort should be true")
	}
	if sc.SourcePortMin != 30000 {
		t.Errorf("SourcePortMin: expected 30000, got %d", sc.SourcePortMin)
	}
	if sc.SourcePortMax != 60000 {
		t.Errorf("SourcePortMax: expected 60000, got %d", sc.SourcePortMax)
	}
	if sc.TimingJitter {
		t.Error("TimingJitter should be false")
	}
	if sc.JitterMaxMS != 0 {
		t.Errorf("JitterMaxMS: expected 0, got %d", sc.JitterMaxMS)
	}
	if sc.ScanID == "" {
		t.Error("ScanID should be generated (non-empty UUID)")
	}
}

// --- processResults ---

func TestProcessResults_CountsOpen(t *testing.T) {
	ch := make(chan *types.ScanResult, 3)
	ch <- &types.ScanResult{IP: "10.0.0.1", Port: 80, State: types.PortOpen, Timestamp: time.Now()}
	ch <- &types.ScanResult{IP: "10.0.0.1", Port: 443, State: types.PortOpen, Timestamp: time.Now()}
	ch <- &types.ScanResult{IP: "10.0.0.1", Port: 22, State: types.PortClosed, Timestamp: time.Now()}
	close(ch)

	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	stats := processResults(ch, nil, false)

	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	buf.ReadFrom(r)

	if stats.open != 2 {
		t.Errorf("open: expected 2, got %d", stats.open)
	}
	if stats.closed != 1 {
		t.Errorf("closed: expected 1, got %d", stats.closed)
	}
	if stats.filtered != 0 {
		t.Errorf("filtered: expected 0, got %d", stats.filtered)
	}

	output := buf.String()
	if output == "" {
		t.Error("expected stdout output for open ports")
	}
}

func TestProcessResults_CountsFiltered(t *testing.T) {
	ch := make(chan *types.ScanResult, 2)
	ch <- &types.ScanResult{IP: "10.0.0.1", Port: 25, State: types.PortFiltered, Timestamp: time.Now()}
	ch <- &types.ScanResult{IP: "10.0.0.1", Port: 110, State: types.PortFiltered, Timestamp: time.Now()}
	close(ch)

	old := os.Stdout
	_, w, _ := os.Pipe()
	os.Stdout = w

	stats := processResults(ch, nil, false)

	w.Close()
	os.Stdout = old

	if stats.filtered != 2 {
		t.Errorf("filtered: expected 2, got %d", stats.filtered)
	}
	if stats.open != 0 {
		t.Errorf("open: expected 0, got %d", stats.open)
	}
}

func TestProcessResults_EmptyChannel(t *testing.T) {
	ch := make(chan *types.ScanResult)
	close(ch)

	old := os.Stdout
	_, w, _ := os.Pipe()
	os.Stdout = w

	stats := processResults(ch, nil, false)

	w.Close()
	os.Stdout = old

	if stats.open != 0 || stats.closed != 0 || stats.filtered != 0 {
		t.Error("empty channel should produce zero stats")
	}
}

func TestProcessResults_Duration(t *testing.T) {
	ch := make(chan *types.ScanResult, 1)
	ch <- &types.ScanResult{IP: "10.0.0.1", Port: 80, State: types.PortOpen, Timestamp: time.Now()}
	close(ch)

	old := os.Stdout
	_, w, _ := os.Pipe()
	os.Stdout = w

	stats := processResults(ch, nil, false)

	w.Close()
	os.Stdout = old

	if stats.duration <= 0 {
		t.Error("duration should be positive")
	}
}

// --- printConfigSummary / printScanSummary ---

func TestPrintConfigSummary_NoError(t *testing.T) {
	config := &YAMLConfig{
		NATS: NATSConfig{URL: "nats://localhost:4222"},
		Synscan: SynscanConfig{
			Target:      TargetConfig{CIDR: "10.0.0.0/24"},
			Network:     NetworkConfig{Interface: "eth0"},
			Performance: PerformanceConfig{RateLimit: 1000, TimeoutMS: 5000},
		},
	}
	// Should not panic
	old := os.Stderr
	_, w, _ := os.Pipe()
	os.Stderr = w
	printConfigSummary(config, 100, true)
	w.Close()
	os.Stderr = old
}

func TestPrintConfigSummary_NATSUnavailable(t *testing.T) {
	config := &YAMLConfig{
		NATS: NATSConfig{URL: "nats://localhost:4222"},
		Synscan: SynscanConfig{
			Target:      TargetConfig{CIDR: "10.0.0.0/24"},
			Performance: PerformanceConfig{RateLimit: 1000, TimeoutMS: 5000},
		},
	}
	old := os.Stderr
	_, w, _ := os.Pipe()
	os.Stderr = w
	printConfigSummary(config, 50, false)
	w.Close()
	os.Stderr = old
}

func TestPrintConfigSummary_NoNATS(t *testing.T) {
	config := &YAMLConfig{
		Synscan: SynscanConfig{
			Target:      TargetConfig{CIDR: "10.0.0.0/24"},
			Performance: PerformanceConfig{RateLimit: 1000, TimeoutMS: 5000},
		},
	}
	old := os.Stderr
	_, w, _ := os.Pipe()
	os.Stderr = w
	printConfigSummary(config, 50, false)
	w.Close()
	os.Stderr = old
}

func TestPrintScanSummary_NoError(t *testing.T) {
	old := os.Stderr
	_, w, _ := os.Pipe()
	os.Stderr = w
	printScanSummary(5*time.Second, 10, 50, 5)
	w.Close()
	os.Stderr = old
}

// --- getDefaultIP ---

func TestGetDefaultIP_ReturnsIPOrNil(t *testing.T) {
	ip := getDefaultIP()
	// Can be nil on systems without non-loopback interfaces
	if ip != nil && ip.To4() == nil {
		t.Error("getDefaultIP should return IPv4 or nil")
	}
}
