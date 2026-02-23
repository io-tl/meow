package randomizer

import (
	"fmt"
	"testing"
)

func pairKey(p Pair) string {
	return fmt.Sprintf("%s:%d", p.IP.String(), p.Port)
}

func TestPairRandomizer_Count(t *testing.T) {
	ips := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5",
		"10.0.0.6", "10.0.0.7", "10.0.0.8", "10.0.0.9", "10.0.0.10"}
	ports := []int{80, 443, 22, 8080, 8443}

	pr, err := NewPairRandomizerFromIPs(ips, ports, 16, 42)
	if err != nil {
		t.Fatal(err)
	}

	if got := pr.Count(); got != 50 {
		t.Errorf("Count() = %d, want 50", got)
	}
}

func TestPairRandomizer_ExhaustAll(t *testing.T) {
	ips := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"}
	ports := []int{80, 443, 22}
	total := len(ips) * len(ports)

	pr, err := NewPairRandomizerFromIPs(ips, ports, 4, 42)
	if err != nil {
		t.Fatal(err)
	}

	seen := make(map[string]struct{})
	count := 0
	for {
		pair, ok := pr.Next()
		if !ok {
			break
		}
		key := pairKey(pair)
		if _, dup := seen[key]; dup {
			t.Fatalf("duplicate pair: %s", key)
		}
		seen[key] = struct{}{}
		count++
	}

	if count != total {
		t.Errorf("got %d pairs, want %d", count, total)
	}

	// Verify all expected pairs are present
	for _, ipStr := range ips {
		for _, port := range ports {
			key := fmt.Sprintf("%s:%d", ipStr, port)
			if _, ok := seen[key]; !ok {
				t.Errorf("missing pair: %s", key)
			}
		}
	}
}

func TestPairRandomizer_Deterministic(t *testing.T) {
	ips := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"}
	ports := []int{80, 443, 22, 8080}
	seed := int64(123456)

	collect := func() []string {
		pr, err := NewPairRandomizerFromIPs(ips, ports, 4, seed)
		if err != nil {
			t.Fatal(err)
		}
		var result []string
		for {
			pair, ok := pr.Next()
			if !ok {
				break
			}
			result = append(result, pairKey(pair))
		}
		return result
	}

	run1 := collect()
	run2 := collect()

	if len(run1) != len(run2) {
		t.Fatalf("different lengths: %d vs %d", len(run1), len(run2))
	}
	for i := range run1 {
		if run1[i] != run2[i] {
			t.Fatalf("mismatch at index %d: %s vs %s", i, run1[i], run2[i])
		}
	}
}

func TestPairRandomizer_IPDistribution(t *testing.T) {
	// 254 IPs × 10 ports — first 100 pairs should touch >50 distinct IPs
	ips := make([]string, 254)
	for i := range 254 {
		ips[i] = fmt.Sprintf("10.0.0.%d", i+1)
	}
	ports := []int{80, 443, 22, 8080, 8443, 3306, 5432, 6379, 27017, 9200}

	pr, err := NewPairRandomizerFromIPs(ips, ports, 4096, 99)
	if err != nil {
		t.Fatal(err)
	}

	distinctIPs := make(map[string]struct{})
	for i := 0; i < 100; i++ {
		pair, ok := pr.Next()
		if !ok {
			t.Fatal("exhausted early")
		}
		distinctIPs[pair.IP.String()] = struct{}{}
	}

	if len(distinctIPs) <= 50 {
		t.Errorf("first 100 pairs only touched %d distinct IPs, want >50", len(distinctIPs))
	}
}

func TestPairRandomizer_SkipToResume(t *testing.T) {
	ips := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"}
	ports := []int{80, 443, 22, 8080}
	seed := int64(777)
	batchSize := 4
	skipN := 7

	// Run 1: consume all pairs
	pr1, _ := NewPairRandomizerFromIPs(ips, ports, batchSize, seed)
	all := make([]string, 0, pr1.Count())
	for {
		pair, ok := pr1.Next()
		if !ok {
			break
		}
		all = append(all, pairKey(pair))
	}

	// Run 2: skip first N, consume rest
	pr2, _ := NewPairRandomizerFromIPs(ips, ports, batchSize, seed)
	pr2.SkipTo(skipN)
	resumed := make([]string, 0, pr2.Count()-skipN)
	for {
		pair, ok := pr2.Next()
		if !ok {
			break
		}
		resumed = append(resumed, pairKey(pair))
	}

	expected := all[skipN:]
	if len(resumed) != len(expected) {
		t.Fatalf("resumed length %d, want %d", len(resumed), len(expected))
	}
	for i := range expected {
		if resumed[i] != expected[i] {
			t.Errorf("mismatch at resumed[%d]: got %s, want %s", i, resumed[i], expected[i])
		}
	}
}

func TestPairRandomizer_SkipToMidBatch(t *testing.T) {
	ips := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}
	ports := []int{80, 443}
	seed := int64(42)
	batchSize := 4
	total := len(ips) * len(ports) // 6

	// Collect all
	pr1, _ := NewPairRandomizerFromIPs(ips, ports, batchSize, seed)
	all := make([]string, 0, total)
	for {
		pair, ok := pr1.Next()
		if !ok {
			break
		}
		all = append(all, pairKey(pair))
	}

	// Skip to middle of first batch (index 2, batch size 4)
	pr2, _ := NewPairRandomizerFromIPs(ips, ports, batchSize, seed)
	pr2.SkipTo(2)
	resumed := make([]string, 0, total-2)
	for {
		pair, ok := pr2.Next()
		if !ok {
			break
		}
		resumed = append(resumed, pairKey(pair))
	}

	expected := all[2:]
	if len(resumed) != len(expected) {
		t.Fatalf("resumed length %d, want %d", len(resumed), len(expected))
	}
	for i := range expected {
		if resumed[i] != expected[i] {
			t.Errorf("mismatch at resumed[%d]: got %s, want %s", i, resumed[i], expected[i])
		}
	}
}

func TestPairRandomizer_SkipToBeyondTotal(t *testing.T) {
	ips := []string{"10.0.0.1", "10.0.0.2"}
	ports := []int{80, 443}

	pr, _ := NewPairRandomizerFromIPs(ips, ports, 4, 42)
	pr.SkipTo(100) // way beyond total=4

	_, ok := pr.Next()
	if ok {
		t.Error("Next() should return false after SkipTo beyond total")
	}
}

func TestPairRandomizer_SingleIP(t *testing.T) {
	ips := []string{"10.0.0.1"}
	ports := []int{80, 443, 22}

	pr, _ := NewPairRandomizerFromIPs(ips, ports, 8, 42)
	if pr.Count() != 3 {
		t.Fatalf("Count() = %d, want 3", pr.Count())
	}

	seen := make(map[string]struct{})
	for {
		pair, ok := pr.Next()
		if !ok {
			break
		}
		if pair.IP.String() != "10.0.0.1" {
			t.Errorf("unexpected IP: %s", pair.IP)
		}
		seen[pairKey(pair)] = struct{}{}
	}
	if len(seen) != 3 {
		t.Errorf("got %d unique pairs, want 3", len(seen))
	}
}

func TestPairRandomizer_SinglePort(t *testing.T) {
	ips := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}
	ports := []int{80}

	pr, _ := NewPairRandomizerFromIPs(ips, ports, 8, 42)
	if pr.Count() != 3 {
		t.Fatalf("Count() = %d, want 3", pr.Count())
	}

	seen := make(map[string]struct{})
	for {
		pair, ok := pr.Next()
		if !ok {
			break
		}
		if pair.Port != 80 {
			t.Errorf("unexpected port: %d", pair.Port)
		}
		seen[pairKey(pair)] = struct{}{}
	}
	if len(seen) != 3 {
		t.Errorf("got %d unique pairs, want 3", len(seen))
	}
}

func TestPairRandomizer_FromCIDR(t *testing.T) {
	// /28 = 16 IPs, 14 usable (skip network + broadcast)
	pr, err := NewPairRandomizerFromCIDR("192.168.1.0/28", []int{80, 443}, 8, 42)
	if err != nil {
		t.Fatal(err)
	}
	if pr.Count() != 28 { // 14 IPs × 2 ports
		t.Fatalf("Count() = %d, want 28", pr.Count())
	}

	seen := make(map[string]struct{})
	for {
		pair, ok := pr.Next()
		if !ok {
			break
		}
		seen[pairKey(pair)] = struct{}{}
	}
	if len(seen) != 28 {
		t.Errorf("got %d unique pairs, want 28", len(seen))
	}
}

func TestPairRandomizer_BatchBoundary(t *testing.T) {
	// batchSize=3, total=6 → exactly 2 full batches
	ips := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}
	ports := []int{80, 443}

	pr, _ := NewPairRandomizerFromIPs(ips, ports, 3, 42)
	seen := make(map[string]struct{})
	count := 0
	for {
		pair, ok := pr.Next()
		if !ok {
			break
		}
		seen[pairKey(pair)] = struct{}{}
		count++
	}

	if count != 6 {
		t.Errorf("got %d pairs, want 6", count)
	}
	if len(seen) != 6 {
		t.Errorf("got %d unique pairs, want 6", len(seen))
	}
}

func TestPairRandomizer_BatchBoundaryOdd(t *testing.T) {
	// batchSize=4, total=6 → batch of 4 + batch of 2
	ips := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}
	ports := []int{80, 443}

	pr, _ := NewPairRandomizerFromIPs(ips, ports, 4, 42)
	seen := make(map[string]struct{})
	count := 0
	for {
		pair, ok := pr.Next()
		if !ok {
			break
		}
		seen[pairKey(pair)] = struct{}{}
		count++
	}

	if count != 6 {
		t.Errorf("got %d pairs, want 6", count)
	}
	if len(seen) != 6 {
		t.Errorf("got %d unique pairs, want 6", len(seen))
	}
}

func TestPairRandomizer_PortDistribution(t *testing.T) {
	// 254 IPs × 20 ports — first 100 pairs should touch >10 distinct ports
	// (before the fix, stride mapping grouped ports together: only ~1-2 ports in 100 pairs)
	ips := make([]string, 254)
	for i := range 254 {
		ips[i] = fmt.Sprintf("10.0.0.%d", i+1)
	}
	ports := []int{80, 443, 22, 8080, 8443, 3306, 5432, 6379, 27017, 9200,
		21, 25, 53, 110, 143, 993, 995, 1433, 3389, 5900}

	pr, err := NewPairRandomizerFromIPs(ips, ports, 4096, 99)
	if err != nil {
		t.Fatal(err)
	}

	distinctPorts := make(map[uint16]struct{})
	for i := 0; i < 100; i++ {
		pair, ok := pr.Next()
		if !ok {
			t.Fatal("exhausted early")
		}
		distinctPorts[pair.Port] = struct{}{}
	}

	if len(distinctPorts) <= 10 {
		t.Errorf("first 100 pairs only touched %d distinct ports, want >10", len(distinctPorts))
	}
}

func TestPairRandomizer_SkipToResumeBatchBoundary(t *testing.T) {
	// Skip exactly at batch boundary
	ips := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"}
	ports := []int{80, 443, 22}
	seed := int64(555)
	batchSize := 4
	skipN := batchSize // skip exactly 1 batch

	pr1, _ := NewPairRandomizerFromIPs(ips, ports, batchSize, seed)
	all := make([]string, 0, pr1.Count())
	for {
		pair, ok := pr1.Next()
		if !ok {
			break
		}
		all = append(all, pairKey(pair))
	}

	pr2, _ := NewPairRandomizerFromIPs(ips, ports, batchSize, seed)
	pr2.SkipTo(skipN)
	resumed := make([]string, 0)
	for {
		pair, ok := pr2.Next()
		if !ok {
			break
		}
		resumed = append(resumed, pairKey(pair))
	}

	expected := all[skipN:]
	if len(resumed) != len(expected) {
		t.Fatalf("resumed length %d, want %d", len(resumed), len(expected))
	}
	for i := range expected {
		if resumed[i] != expected[i] {
			t.Errorf("mismatch at resumed[%d]: got %s, want %s", i, resumed[i], expected[i])
		}
	}
}
