package randomizer

import (
	"math/rand"
	"net"
)

// IPRandomizer randomizes IP addresses from a CIDR block in batches
type IPRandomizer struct {
	baseIP    uint32
	totalIPs  uint32
	remaining uint32
	batchSize uint32
	rng       *rand.Rand
	current   []uint32
	index     int
}

// NewIPRandomizer creates a randomizer for a CIDR block
func NewIPRandomizer(cidr string, batchSize uint32, seed int64) (*IPRandomizer, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	// Convert IP to uint32
	baseIP := ipToUint32(ip.Mask(ipNet.Mask))
	ones, bits := ipNet.Mask.Size()
	totalIPs := uint32(1 << (bits - ones))

	// For /31 and /32, don't skip network/broadcast (RFC 3021)
	var skipFirst, skipLast uint32
	if ones < 31 {
		skipFirst = 1 // Skip network address
		skipLast = 1  // Skip broadcast address
	}

	usableIPs := totalIPs - skipFirst - skipLast
	return &IPRandomizer{
		baseIP:    baseIP + skipFirst,
		totalIPs:  usableIPs,
		remaining: usableIPs,
		batchSize: batchSize,
		rng:       rand.New(rand.NewSource(seed)),
		current:   make([]uint32, 0, batchSize),
		index:     0,
	}, nil
}

// Next returns the next randomized IP
func (r *IPRandomizer) Next() (net.IP, bool) {
	// Reload next batch if necessary
	if r.index >= len(r.current) {
		if !r.loadNextBatch() {
			return nil, false // Done
		}
	}

	ip := uint32ToIP(r.current[r.index])
	r.index++
	return ip, true
}

func (r *IPRandomizer) loadNextBatch() bool {
	if r.remaining == 0 {
		return false
	}

	// Current batch size
	batchSize := r.batchSize
	// If batchSize is 0, use a default value
	if batchSize == 0 {
		batchSize = 1024
	}
	if batchSize > r.remaining {
		batchSize = r.remaining
	}

	// Generate sequential batch
	r.current = r.current[:0]
	for i := uint32(0); i < batchSize; i++ {
		r.current = append(r.current, r.baseIP+i)
	}

	// Shuffle the batch
	r.shuffleBatch()

	// Advance for next batch
	r.baseIP += batchSize
	r.remaining -= batchSize
	r.index = 0

	return true
}

func (r *IPRandomizer) shuffleBatch() {
	r.rng.Shuffle(len(r.current), func(i, j int) {
		r.current[i], r.current[j] = r.current[j], r.current[i]
	})
}

// Count returns the total number of IPs in the CIDR block
func (r *IPRandomizer) Count() int {
	return int(r.totalIPs)
}

// IP <-> uint32 conversion helpers
func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func uint32ToIP(n uint32) net.IP {
	return net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}

// IPListRandomizer randomizes IPs from a provided list in batches
type IPListRandomizer struct {
	ips       []uint32
	batchSize uint32
	rng       *rand.Rand
	current   []uint32
	index     int
	pos       int
}

// NewIPListRandomizer creates a randomizer from a list of IP strings
func NewIPListRandomizer(ipStrings []string, batchSize uint32, seed int64) (*IPListRandomizer, error) {
	ips := make([]uint32, 0, len(ipStrings))
	for _, ipStr := range ipStrings {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		ips = append(ips, ipToUint32(ip.To4()))
	}

	return &IPListRandomizer{
		ips:       ips,
		batchSize: batchSize,
		rng:       rand.New(rand.NewSource(seed)),
		current:   make([]uint32, 0, batchSize),
		index:     0,
		pos:       0,
	}, nil
}

// Next returns the next randomized IP from the list
func (r *IPListRandomizer) Next() (net.IP, bool) {
	// Reload next batch if necessary
	if r.index >= len(r.current) {
		if !r.loadNextBatch() {
			return nil, false // Done
		}
	}

	ip := uint32ToIP(r.current[r.index])
	r.index++
	return ip, true
}

func (r *IPListRandomizer) loadNextBatch() bool {
	if r.pos >= len(r.ips) {
		return false
	}

	// Current batch size
	batchSize := int(r.batchSize)
	// If batchSize is 0, use a default value
	if batchSize == 0 {
		batchSize = 1024
	}
	remaining := len(r.ips) - r.pos
	if batchSize > remaining {
		batchSize = remaining
	}

	// Copy next batch
	r.current = r.current[:0]
	for i := 0; i < batchSize; i++ {
		r.current = append(r.current, r.ips[r.pos+i])
	}

	// Shuffle the batch
	r.shuffleBatch()

	// Advance for next batch
	r.pos += batchSize
	r.index = 0

	return true
}

func (r *IPListRandomizer) shuffleBatch() {
	r.rng.Shuffle(len(r.current), func(i, j int) {
		r.current[i], r.current[j] = r.current[j], r.current[i]
	})
}

// Count returns the total number of IPs
func (r *IPListRandomizer) Count() int {
	return len(r.ips)
}
