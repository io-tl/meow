package randomizer

import (
	"math/rand"
	"sync"
	"time"
)

// SourcePortPool manages randomized source port allocation
type SourcePortPool struct {
	minPort uint16
	maxPort uint16
	rng     *rand.Rand
	used    map[uint16]bool
	mu      sync.Mutex
}

// NewSourcePortPool creates a source port pool
func NewSourcePortPool(minPort, maxPort uint16) *SourcePortPool {
	return &SourcePortPool{
		minPort: minPort,
		maxPort: maxPort,
		rng:     rand.New(rand.NewSource(time.Now().UnixNano())),
		used:    make(map[uint16]bool),
	}
}

// GetRandomPort returns a random available source port
func (p *SourcePortPool) GetRandomPort() uint16 {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Number of ports in range
	rangeSize := int(p.maxPort - p.minPort + 1)

	// Avoid infinite loop if all ports are used
	if len(p.used) >= rangeSize {
		// Release a random port
		for port := range p.used {
			delete(p.used, port)
			break
		}
	}

	// Find an available port
	var port uint16
	for {
		port = p.minPort + uint16(p.rng.Intn(rangeSize))
		if !p.used[port] {
			p.used[port] = true
			break
		}
	}

	return port
}

// ReleasePort releases a source port
func (p *SourcePortPool) ReleasePort(port uint16) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.used, port)
}
