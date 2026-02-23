package randomizer

import (
	"sync"
	"testing"
)

func TestSourcePortPool_PortInRange(t *testing.T) {
	pool := NewSourcePortPool(30000, 60000)
	for i := 0; i < 100; i++ {
		port := pool.GetRandomPort()
		if port < 30000 || port > 60000 {
			t.Errorf("port %d out of range [30000, 60000]", port)
		}
		pool.ReleasePort(port)
	}
}

func TestSourcePortPool_NoDuplicates(t *testing.T) {
	pool := NewSourcePortPool(40000, 40010)
	seen := make(map[uint16]bool)

	// Allocate all ports in range (11 ports: 40000-40010)
	for i := 0; i < 11; i++ {
		port := pool.GetRandomPort()
		if seen[port] {
			t.Errorf("duplicate port allocated: %d", port)
		}
		seen[port] = true
	}
}

func TestSourcePortPool_ReleaseAllowsReuse(t *testing.T) {
	pool := NewSourcePortPool(50000, 50000) // Only 1 port
	port1 := pool.GetRandomPort()
	if port1 != 50000 {
		t.Errorf("expected 50000, got %d", port1)
	}

	pool.ReleasePort(port1)

	port2 := pool.GetRandomPort()
	if port2 != 50000 {
		t.Errorf("after release, expected 50000, got %d", port2)
	}
}

func TestSourcePortPool_ExhaustionRecovery(t *testing.T) {
	// Small range: only 3 ports
	pool := NewSourcePortPool(50000, 50002)

	// Allocate all 3
	for i := 0; i < 3; i++ {
		pool.GetRandomPort()
	}

	// Next allocation should still succeed (forces release of a random port)
	port := pool.GetRandomPort()
	if port < 50000 || port > 50002 {
		t.Errorf("port %d out of range after exhaustion recovery", port)
	}
}

func TestSourcePortPool_Concurrent(t *testing.T) {
	pool := NewSourcePortPool(30000, 60000)
	var wg sync.WaitGroup
	errors := make(chan error, 100)

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			port := pool.GetRandomPort()
			if port < 30000 || port > 60000 {
				errors <- &portRangeError{port: port}
			}
			pool.ReleasePort(port)
		}()
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Error(err)
	}
}

type portRangeError struct {
	port uint16
}

func (e *portRangeError) Error() string {
	return "port out of range"
}

func TestSourcePortPool_AllocateReleaseCycle(t *testing.T) {
	pool := NewSourcePortPool(40000, 40004) // 5 ports

	// Allocate and release in cycles
	for cycle := 0; cycle < 10; cycle++ {
		ports := make([]uint16, 5)
		for i := 0; i < 5; i++ {
			ports[i] = pool.GetRandomPort()
		}
		for _, p := range ports {
			pool.ReleasePort(p)
		}
	}
}

func TestSourcePortPool_ReleaseUnusedPort(t *testing.T) {
	pool := NewSourcePortPool(40000, 40010)
	// Releasing a port that was never allocated should not panic
	pool.ReleasePort(40005)
}

func TestSourcePortPool_MinEqualMax(t *testing.T) {
	pool := NewSourcePortPool(50000, 50000)
	port := pool.GetRandomPort()
	if port != 50000 {
		t.Errorf("single port pool: expected 50000, got %d", port)
	}
}

func TestSourcePortPool_ConcurrentAllocRelease(t *testing.T) {
	pool := NewSourcePortPool(30000, 30100) // 101 ports
	var wg sync.WaitGroup

	// Simulate concurrent scan traffic: multiple goroutines allocating and releasing
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				port := pool.GetRandomPort()
				// Simulate some work
				pool.ReleasePort(port)
			}
		}()
	}

	wg.Wait()
}
