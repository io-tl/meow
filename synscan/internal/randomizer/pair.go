package randomizer

import (
	"math/rand"
	"net"
)

// Pair represents an (IP, port) combination to scan.
type Pair struct {
	IP   net.IP
	Port uint16
}

// PairRandomizer generates randomized (IP, port) pairs using a multiplicative
// permutation and per-batch shuffling. A stride coprime to total maps linear
// indices across both IP and port dimensions, so consecutive pairs touch
// different IPs AND different ports. Each batch is independently shuffled
// with a deterministic seed, enabling O(1) resume via SkipTo.
type PairRandomizer struct {
	ips      []uint32 // globally shuffled IPs
	ports    []uint16 // globally shuffled ports
	numIPs   int
	numPorts int
	total    int // numIPs * numPorts

	batchSize  int
	seed       int64
	stride     int // coprime to total, spreads indices across both dimensions
	batch      []int // linear indices for current batch
	batchIdx   int   // position within current batch
	nextLinear int   // next linear index to load into a batch
}

const pairBatchPrime = 6364136223846793005

// NewPairRandomizerFromIPs creates a PairRandomizer from a list of IP strings.
func NewPairRandomizerFromIPs(ipStrings []string, ports []int, batchSize int, seed int64) (*PairRandomizer, error) {
	ips := make([]uint32, 0, len(ipStrings))
	for _, ipStr := range ipStrings {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		ips = append(ips, ipToUint32(ip.To4()))
	}
	return newPairRandomizer(ips, ports, batchSize, seed), nil
}

// NewPairRandomizerFromCIDR creates a PairRandomizer from a CIDR block.
func NewPairRandomizerFromCIDR(cidr string, ports []int, batchSize int, seed int64) (*PairRandomizer, error) {
	ips, err := expandCIDRToUint32(cidr)
	if err != nil {
		return nil, err
	}
	return newPairRandomizer(ips, ports, batchSize, seed), nil
}

// expandCIDRToUint32 expands a CIDR to a slice of usable host uint32 addresses,
// skipping network and broadcast for prefixes shorter than /31.
func expandCIDRToUint32(cidr string) ([]uint32, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	baseIP := ipToUint32(ip.Mask(ipNet.Mask))
	ones, bits := ipNet.Mask.Size()
	totalIPs := uint32(1 << (bits - ones))

	var skipFirst, skipLast uint32
	if ones < 31 {
		skipFirst = 1
		skipLast = 1
	}

	usable := totalIPs - skipFirst - skipLast
	ips := make([]uint32, usable)
	start := baseIP + skipFirst
	for i := range usable {
		ips[i] = start + i
	}
	return ips, nil
}

func newPairRandomizer(ips []uint32, ports []int, batchSize int, seed int64) *PairRandomizer {
	if batchSize <= 0 {
		batchSize = 4096
	}

	numIPs := len(ips)
	numPorts := len(ports)
	total := numIPs * numPorts

	// Global shuffle of IPs and ports with the same seed-derived RNG
	rng := rand.New(rand.NewSource(seed))
	rng.Shuffle(numIPs, func(i, j int) { ips[i], ips[j] = ips[j], ips[i] })

	ports16 := make([]uint16, numPorts)
	for i, p := range ports {
		ports16[i] = uint16(p)
	}
	rng.Shuffle(numPorts, func(i, j int) { ports16[i], ports16[j] = ports16[j], ports16[i] })

	// Compute a stride coprime to total for the multiplicative permutation.
	// This spreads consecutive linear indices across both IP and port dimensions.
	stride := findCoprime(total, seed)

	return &PairRandomizer{
		ips:        ips,
		ports:      ports16,
		numIPs:     numIPs,
		numPorts:   numPorts,
		total:      total,
		batchSize:  batchSize,
		seed:       seed,
		stride:     stride,
		batch:      make([]int, 0, batchSize),
		batchIdx:   0,
		nextLinear: 0,
	}
}

// Next returns the next randomized (IP, port) pair.
// Returns false when all pairs have been exhausted.
func (pr *PairRandomizer) Next() (Pair, bool) {
	if pr.batchIdx >= len(pr.batch) {
		if !pr.loadNextBatch() {
			return Pair{}, false
		}
	}

	idx := pr.batch[pr.batchIdx]
	pr.batchIdx++

	// Multiplicative permutation: maps linear index to a position spread
	// across both IP and port dimensions (bijection since gcd(stride, total) == 1)
	mapped := int((int64(idx) * int64(pr.stride)) % int64(pr.total))
	ipIdx := mapped % pr.numIPs
	portIdx := mapped / pr.numIPs

	return Pair{
		IP:   uint32ToIP(pr.ips[ipIdx]),
		Port: pr.ports[portIdx],
	}, true
}

// SkipTo jumps to the given linear offset in O(1).
// The next call to Next() will return the pair at that offset within its batch.
func (pr *PairRandomizer) SkipTo(offset int) {
	if offset >= pr.total {
		pr.nextLinear = pr.total
		pr.batch = pr.batch[:0]
		pr.batchIdx = 0
		return
	}

	// Which batch does this offset fall in?
	batchNum := offset / pr.batchSize
	posInBatch := offset % pr.batchSize

	// Set nextLinear to the start of that batch and load it
	pr.nextLinear = batchNum * pr.batchSize
	pr.loadNextBatch()

	// Advance within the loaded batch
	pr.batchIdx = posInBatch
}

// Count returns the total number of (IP, port) pairs.
func (pr *PairRandomizer) Count() int {
	return pr.total
}

// findCoprime returns a stride coprime to n, derived from seed for determinism.
// The stride is used for a bijective multiplicative permutation over [0, n).
func findCoprime(n int, seed int64) int {
	if n <= 1 {
		return 1
	}
	// Derive a candidate from the seed
	rng := rand.New(rand.NewSource(seed ^ 0x517CC1B727220A95))
	candidate := rng.Intn(n-1) + 1 // [1, n-1]
	// Walk forward until we find a coprime
	for gcd(candidate, n) != 1 {
		candidate++
		if candidate >= n {
			candidate = 1
		}
	}
	return candidate
}

func gcd(a, b int) int {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}

func (pr *PairRandomizer) loadNextBatch() bool {
	if pr.nextLinear >= pr.total {
		return false
	}

	remaining := pr.total - pr.nextLinear
	size := min(pr.batchSize, remaining)

	// Fill batch with sequential linear indices
	pr.batch = pr.batch[:size]
	for i := range size {
		pr.batch[i] = pr.nextLinear + i
	}

	// Deterministic per-batch shuffle: seed derived from batch number
	batchNum := pr.nextLinear / pr.batchSize
	batchRNG := rand.New(rand.NewSource(pr.seed ^ (int64(batchNum) * pairBatchPrime)))
	batchRNG.Shuffle(size, func(i, j int) { pr.batch[i], pr.batch[j] = pr.batch[j], pr.batch[i] })

	pr.nextLinear += size
	pr.batchIdx = 0
	return true
}
