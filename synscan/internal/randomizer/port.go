package randomizer

import (
	"math/rand"
)

// PortRandomizer randomizes port scan order
type PortRandomizer struct {
	ports []int
	rng   *rand.Rand
	index int
}

// NewPortRandomizer creates a port randomizer
func NewPortRandomizer(ports []int, seed int64) *PortRandomizer {
	// Copy ports to avoid modifying original
	portsCopy := make([]int, len(ports))
	copy(portsCopy, ports)

	pr := &PortRandomizer{
		ports: portsCopy,
		rng:   rand.New(rand.NewSource(seed)),
		index: 0,
	}

	// Initial shuffle
	pr.shuffle()
	return pr
}

func (pr *PortRandomizer) shuffle() {
	pr.rng.Shuffle(len(pr.ports), func(i, j int) {
		pr.ports[i], pr.ports[j] = pr.ports[j], pr.ports[i]
	})
}

// Reset re-shuffles ports for a new IP
func (pr *PortRandomizer) Reset() {
	pr.shuffle()
	pr.index = 0
}

// Next returns the next port in randomized order
func (pr *PortRandomizer) Next() (int, bool) {
	if pr.index >= len(pr.ports) {
		return 0, false
	}
	port := pr.ports[pr.index]
	pr.index++
	return port, true
}

// GetShuffled returns all ports in randomized order
func (pr *PortRandomizer) GetShuffled() []int {
	pr.Reset()
	return pr.ports
}
