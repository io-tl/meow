package main

import "testing"

func TestTopPortsReturnsRequestedCount(t *testing.T) {
	ports, err := TopPorts(10)
	if err != nil {
		t.Fatalf("TopPorts(10) returned error: %v", err)
	}
	if len(ports) != 10 {
		t.Fatalf("expected 10 ports, got %d", len(ports))
	}
}

func TestTopPortsFirstIsPort80(t *testing.T) {
	ports, err := TopPorts(1)
	if err != nil {
		t.Fatalf("TopPorts(1) returned error: %v", err)
	}
	if ports[0] != 80 {
		t.Fatalf("expected first port to be 80, got %d", ports[0])
	}
}

func TestTopPortsZeroReturnsError(t *testing.T) {
	_, err := TopPorts(0)
	if err == nil {
		t.Fatal("expected error for TopPorts(0)")
	}
}

func TestTopPortsNegativeReturnsError(t *testing.T) {
	_, err := TopPorts(-5)
	if err == nil {
		t.Fatal("expected error for TopPorts(-5)")
	}
}

func TestTopPortsClampsToMax(t *testing.T) {
	ports, err := TopPorts(99999)
	if err != nil {
		t.Fatalf("TopPorts(99999) returned error: %v", err)
	}
	if len(ports) != len(topPortsTCP) {
		t.Fatalf("expected %d ports (clamped), got %d", len(topPortsTCP), len(ports))
	}
}

func TestTopPortsNoDuplicates(t *testing.T) {
	ports, err := TopPorts(len(topPortsTCP))
	if err != nil {
		t.Fatalf("TopPorts returned error: %v", err)
	}
	seen := make(map[uint16]bool, len(ports))
	for i, p := range ports {
		if seen[p] {
			t.Fatalf("duplicate port %d at index %d", p, i)
		}
		seen[p] = true
	}
}

func TestTopPortsAllInValidRange(t *testing.T) {
	ports, err := TopPorts(len(topPortsTCP))
	if err != nil {
		t.Fatalf("TopPorts returned error: %v", err)
	}
	for i, p := range ports {
		if p == 0 || p > 65535 {
			t.Fatalf("port %d at index %d out of range 1-65535", p, i)
		}
	}
}

func TestTopPortsReturnsCopy(t *testing.T) {
	ports1, _ := TopPorts(5)
	ports2, _ := TopPorts(5)
	ports1[0] = 65535
	if ports2[0] == 65535 {
		t.Fatal("TopPorts should return a copy, not a reference to the original")
	}
}
