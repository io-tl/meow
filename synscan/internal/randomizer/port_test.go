package randomizer

import (
	"sort"
	"testing"
)

func TestPortRandomizer_AllPortsReturned(t *testing.T) {
	ports := []int{80, 443, 22, 8080, 3306}
	pr := NewPortRandomizer(ports, 42)

	var result []int
	for {
		p, ok := pr.Next()
		if !ok {
			break
		}
		result = append(result, p)
	}

	if len(result) != len(ports) {
		t.Fatalf("expected %d ports, got %d", len(ports), len(result))
	}

	// All original ports should be present
	sort.Ints(result)
	expected := make([]int, len(ports))
	copy(expected, ports)
	sort.Ints(expected)
	for i := range expected {
		if result[i] != expected[i] {
			t.Errorf("port[%d]: expected %d, got %d", i, expected[i], result[i])
		}
	}
}

func TestPortRandomizer_Deterministic(t *testing.T) {
	ports := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	seed := int64(12345)

	collect := func() []int {
		pr := NewPortRandomizer(ports, seed)
		var result []int
		for {
			p, ok := pr.Next()
			if !ok {
				break
			}
			result = append(result, p)
		}
		return result
	}

	r1 := collect()
	r2 := collect()

	for i := range r1 {
		if r1[i] != r2[i] {
			t.Errorf("port[%d] differs: %d vs %d", i, r1[i], r2[i])
			break
		}
	}
}

func TestPortRandomizer_DifferentSeeds(t *testing.T) {
	ports := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}

	collect := func(seed int64) []int {
		pr := NewPortRandomizer(ports, seed)
		var result []int
		for {
			p, ok := pr.Next()
			if !ok {
				break
			}
			result = append(result, p)
		}
		return result
	}

	r1 := collect(1)
	r2 := collect(2)

	same := true
	for i := range r1 {
		if r1[i] != r2[i] {
			same = false
			break
		}
	}
	if same {
		t.Error("different seeds should (most likely) produce different orders")
	}
}

func TestPortRandomizer_DoesNotModifyOriginal(t *testing.T) {
	original := []int{80, 443, 22}
	copyBefore := make([]int, len(original))
	copy(copyBefore, original)

	NewPortRandomizer(original, 42)

	for i := range original {
		if original[i] != copyBefore[i] {
			t.Errorf("original[%d] modified: was %d, now %d", i, copyBefore[i], original[i])
		}
	}
}

func TestPortRandomizer_SinglePort(t *testing.T) {
	pr := NewPortRandomizer([]int{80}, 42)
	p, ok := pr.Next()
	if !ok {
		t.Fatal("expected a port")
	}
	if p != 80 {
		t.Errorf("expected 80, got %d", p)
	}
	_, ok = pr.Next()
	if ok {
		t.Error("expected false after single port exhausted")
	}
}

func TestPortRandomizer_EmptyPorts(t *testing.T) {
	pr := NewPortRandomizer([]int{}, 42)
	_, ok := pr.Next()
	if ok {
		t.Error("expected false for empty ports")
	}
}

func TestPortRandomizer_Reset(t *testing.T) {
	ports := []int{1, 2, 3, 4, 5}
	pr := NewPortRandomizer(ports, 42)

	// Exhaust first round
	var first []int
	for {
		p, ok := pr.Next()
		if !ok {
			break
		}
		first = append(first, p)
	}

	// Reset and collect again
	pr.Reset()
	var second []int
	for {
		p, ok := pr.Next()
		if !ok {
			break
		}
		second = append(second, p)
	}

	// Both rounds should have the same ports (different order after re-shuffle)
	if len(first) != len(second) {
		t.Fatalf("lengths differ: %d vs %d", len(first), len(second))
	}

	sort.Ints(first)
	sort.Ints(second)
	for i := range first {
		if first[i] != second[i] {
			t.Errorf("different ports after reset at index %d", i)
		}
	}
}

func TestPortRandomizer_GetShuffled(t *testing.T) {
	ports := []int{80, 443, 22, 8080}
	pr := NewPortRandomizer(ports, 42)

	shuffled := pr.GetShuffled()
	if len(shuffled) != len(ports) {
		t.Fatalf("expected %d ports, got %d", len(ports), len(shuffled))
	}

	// Same ports present
	sort.Ints(shuffled)
	expected := make([]int, len(ports))
	copy(expected, ports)
	sort.Ints(expected)
	for i := range expected {
		if shuffled[i] != expected[i] {
			t.Errorf("port[%d]: expected %d, got %d", i, expected[i], shuffled[i])
		}
	}
}

func TestPortRandomizer_IsShuffled(t *testing.T) {
	// With enough ports and a seed, the order should differ from input
	ports := make([]int, 100)
	for i := range ports {
		ports[i] = i + 1
	}
	pr := NewPortRandomizer(ports, 42)

	var result []int
	for {
		p, ok := pr.Next()
		if !ok {
			break
		}
		result = append(result, p)
	}

	// Check it's not in original order (probability of same order with 100 elements is ~0)
	inOrder := true
	for i := range result {
		if result[i] != i+1 {
			inOrder = false
			break
		}
	}
	if inOrder {
		t.Error("ports should be shuffled, but appear in original order")
	}
}
