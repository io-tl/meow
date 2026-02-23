package randomizer

import (
	"net"
	"testing"
)

// --- IPRandomizer ---

func TestIPRandomizer_Count24(t *testing.T) {
	r, err := NewIPRandomizer("192.168.1.0/24", 256, 42)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// /24 = 256 - 2 (net + broadcast) = 254
	if r.Count() != 254 {
		t.Errorf("expected 254 IPs, got %d", r.Count())
	}
}

func TestIPRandomizer_Count32(t *testing.T) {
	r, err := NewIPRandomizer("10.0.0.1/32", 1, 42)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Count() != 1 {
		t.Errorf("expected 1 IP for /32, got %d", r.Count())
	}
}

func TestIPRandomizer_Count31(t *testing.T) {
	r, err := NewIPRandomizer("10.0.0.0/31", 4, 42)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// /31 RFC 3021: no skip
	if r.Count() != 2 {
		t.Errorf("expected 2 IPs for /31, got %d", r.Count())
	}
}

func TestIPRandomizer_Count16(t *testing.T) {
	r, err := NewIPRandomizer("10.0.0.0/16", 4096, 42)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// /16 = 65536 - 2 = 65534
	if r.Count() != 65534 {
		t.Errorf("expected 65534 IPs, got %d", r.Count())
	}
}

func TestIPRandomizer_ExhaustAll(t *testing.T) {
	r, err := NewIPRandomizer("10.0.0.0/28", 16, 42)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// /28 = 16 - 2 = 14 usable IPs
	count := 0
	seen := make(map[string]bool)
	for {
		ip, ok := r.Next()
		if !ok {
			break
		}
		ipStr := ip.String()
		if seen[ipStr] {
			t.Errorf("duplicate IP: %s", ipStr)
		}
		seen[ipStr] = true
		count++
	}
	if count != 14 {
		t.Errorf("expected 14 IPs, got %d", count)
	}
}

func TestIPRandomizer_NextReturnsFalseWhenExhausted(t *testing.T) {
	r, err := NewIPRandomizer("10.0.0.0/30", 4, 42)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// /30 = 4 - 2 = 2 IPs
	for i := 0; i < 2; i++ {
		_, ok := r.Next()
		if !ok {
			t.Fatalf("expected IP at iteration %d", i)
		}
	}
	_, ok := r.Next()
	if ok {
		t.Error("expected false after exhaustion")
	}
}

func TestIPRandomizer_Deterministic(t *testing.T) {
	seed := int64(12345)
	cidr := "192.168.1.0/24"

	var ips1, ips2 []string
	for _, ips := range []*[]string{&ips1, &ips2} {
		r, _ := NewIPRandomizer(cidr, 256, seed)
		for {
			ip, ok := r.Next()
			if !ok {
				break
			}
			*ips = append(*ips, ip.String())
		}
	}

	if len(ips1) != len(ips2) {
		t.Fatalf("lengths differ: %d vs %d", len(ips1), len(ips2))
	}
	for i := range ips1 {
		if ips1[i] != ips2[i] {
			t.Errorf("IP[%d] differs: %s vs %s", i, ips1[i], ips2[i])
			break
		}
	}
}

func TestIPRandomizer_DifferentSeedsDifferentOrder(t *testing.T) {
	cidr := "10.0.0.0/24"

	collect := func(seed int64) []string {
		r, _ := NewIPRandomizer(cidr, 256, seed)
		var ips []string
		for {
			ip, ok := r.Next()
			if !ok {
				break
			}
			ips = append(ips, ip.String())
		}
		return ips
	}

	ips1 := collect(1)
	ips2 := collect(2)

	same := true
	for i := range ips1 {
		if ips1[i] != ips2[i] {
			same = false
			break
		}
	}
	if same {
		t.Error("different seeds should produce different orders")
	}
}

func TestIPRandomizer_AllIPsInRange(t *testing.T) {
	r, err := NewIPRandomizer("10.0.0.0/28", 8, 42)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for {
		ip, ok := r.Next()
		if !ok {
			break
		}
		ip4 := ip.To4()
		if ip4 == nil {
			t.Fatalf("non-IPv4: %v", ip)
		}
		// /28 from 10.0.0.0: usable range is 10.0.0.1 - 10.0.0.14
		last := ip4[3]
		if last < 1 || last > 14 {
			t.Errorf("IP out of range: %s (last octet=%d)", ip, last)
		}
	}
}

func TestIPRandomizer_MultipleBatches(t *testing.T) {
	// Use small batch size to force multiple batches
	r, err := NewIPRandomizer("192.168.0.0/24", 16, 42)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	count := 0
	seen := make(map[string]bool)
	for {
		ip, ok := r.Next()
		if !ok {
			break
		}
		s := ip.String()
		if seen[s] {
			t.Errorf("duplicate across batches: %s", s)
		}
		seen[s] = true
		count++
	}
	if count != 254 {
		t.Errorf("expected 254 IPs, got %d", count)
	}
}

func TestIPRandomizer_InvalidCIDR(t *testing.T) {
	_, err := NewIPRandomizer("not-a-cidr", 256, 42)
	if err == nil {
		t.Error("expected error for invalid CIDR")
	}
}

func TestIPRandomizer_BatchSizeZero(t *testing.T) {
	r, err := NewIPRandomizer("10.0.0.0/30", 0, 42)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// batchSize=0 should use default 1024 internally
	count := 0
	for {
		_, ok := r.Next()
		if !ok {
			break
		}
		count++
	}
	if count != 2 {
		t.Errorf("expected 2 IPs for /30, got %d", count)
	}
}

// --- IPListRandomizer ---

func TestIPListRandomizer_Basic(t *testing.T) {
	ips := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}
	r, err := NewIPListRandomizer(ips, 10, 42)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Count() != 3 {
		t.Errorf("expected 3 IPs, got %d", r.Count())
	}
}

func TestIPListRandomizer_ExhaustAll(t *testing.T) {
	input := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"}
	r, _ := NewIPListRandomizer(input, 10, 42)

	seen := make(map[string]bool)
	count := 0
	for {
		ip, ok := r.Next()
		if !ok {
			break
		}
		s := ip.String()
		if seen[s] {
			t.Errorf("duplicate IP: %s", s)
		}
		seen[s] = true
		count++
	}
	if count != 5 {
		t.Errorf("expected 5 IPs, got %d", count)
	}
}

func TestIPListRandomizer_Deterministic(t *testing.T) {
	input := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"}
	seed := int64(9999)

	var ips1, ips2 []string
	for _, ips := range []*[]string{&ips1, &ips2} {
		r, _ := NewIPListRandomizer(input, 10, seed)
		for {
			ip, ok := r.Next()
			if !ok {
				break
			}
			*ips = append(*ips, ip.String())
		}
	}

	for i := range ips1 {
		if ips1[i] != ips2[i] {
			t.Errorf("IP[%d] differs: %s vs %s", i, ips1[i], ips2[i])
			break
		}
	}
}

func TestIPListRandomizer_SkipsInvalidIPs(t *testing.T) {
	input := []string{"10.0.0.1", "not-an-ip", "10.0.0.3"}
	r, _ := NewIPListRandomizer(input, 10, 42)
	if r.Count() != 2 {
		t.Errorf("expected 2 valid IPs, got %d", r.Count())
	}
}

func TestIPListRandomizer_EmptyList(t *testing.T) {
	r, _ := NewIPListRandomizer([]string{}, 10, 42)
	if r.Count() != 0 {
		t.Errorf("expected 0 IPs, got %d", r.Count())
	}
	_, ok := r.Next()
	if ok {
		t.Error("expected false for empty list")
	}
}

func TestIPListRandomizer_MultipleBatches(t *testing.T) {
	var input []string
	for i := 1; i <= 100; i++ {
		input = append(input, net.IPv4(10, 0, 0, byte(i)).String())
	}
	// Small batch to force multiple batches
	r, _ := NewIPListRandomizer(input, 8, 42)

	seen := make(map[string]bool)
	count := 0
	for {
		ip, ok := r.Next()
		if !ok {
			break
		}
		s := ip.String()
		if seen[s] {
			t.Errorf("duplicate across batches: %s", s)
		}
		seen[s] = true
		count++
	}
	if count != 100 {
		t.Errorf("expected 100 IPs, got %d", count)
	}
}

func TestIPListRandomizer_BatchSizeZero(t *testing.T) {
	input := []string{"10.0.0.1", "10.0.0.2"}
	r, _ := NewIPListRandomizer(input, 0, 42)

	count := 0
	for {
		_, ok := r.Next()
		if !ok {
			break
		}
		count++
	}
	if count != 2 {
		t.Errorf("expected 2 IPs with batchSize=0, got %d", count)
	}
}

// --- ipToUint32 / uint32ToIP ---

func TestIPConversion_Roundtrip(t *testing.T) {
	tests := []string{
		"0.0.0.0",
		"255.255.255.255",
		"192.168.1.1",
		"10.0.0.1",
		"172.16.0.1",
		"127.0.0.1",
	}
	for _, ipStr := range tests {
		ip := net.ParseIP(ipStr)
		n := ipToUint32(ip)
		back := uint32ToIP(n)
		if !ip.To4().Equal(back.To4()) {
			t.Errorf("roundtrip failed for %s: got %s (uint32=%d)", ipStr, back, n)
		}
	}
}

func TestIPToUint32_KnownValues(t *testing.T) {
	tests := []struct {
		ip       string
		expected uint32
	}{
		{"0.0.0.0", 0},
		{"0.0.0.1", 1},
		{"0.0.1.0", 256},
		{"0.1.0.0", 65536},
		{"1.0.0.0", 16777216},
		{"255.255.255.255", 4294967295},
		{"192.168.1.1", 0xC0A80101},
	}
	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		got := ipToUint32(ip)
		if got != tt.expected {
			t.Errorf("ipToUint32(%s): expected %d, got %d", tt.ip, tt.expected, got)
		}
	}
}
