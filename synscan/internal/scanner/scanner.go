package scanner

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"meow/synscan/internal/packet"
	"meow/synscan/internal/randomizer"
	"meow/synscan/internal/transport"
	"meow/synscan/pkg/types"
)

const defaultBatchSize = 64

// Scanner performs TCP SYN scans
type Scanner struct {
	config      *types.ScanConfig
	forger      *packet.Forger
	transport   transport.Transport
	limiter     *JitteredLimiter
	srcPortPool *randomizer.SourcePortPool
	results     chan *types.ScanResult

	// Track pending scans: srcPort -> (ip, dstPort, sendTime)
	pending     map[uint16]*pendingScan
	pendingLock sync.Mutex

	// Track completion and progress
	totalScans  int
	doneScans   int
	packetsSent atomic.Int64
	doneLock    sync.Mutex

	// Packet batch for transport
	packetBatch []*transport.Packet

	// Signal sender completion (receiver owns closing results)
	senderDone chan struct{}

	// Dedup open port results (source port reuse can cause false matches)
	seen     map[uint64]struct{}
	seenLock sync.Mutex

	// Error tracking
	sendErrors      int
	bufferErrors    int
	errorLock       sync.Mutex
	bufferWarnShown bool
}

type pendingScan struct {
	ip       net.IP
	port     uint16
	sendTime time.Time
}

// portKey packs an IPv4 address and port into a uint64 for dedup lookup
func portKey(ip net.IP, port uint16) uint64 {
	ip4 := ip.To4()
	return uint64(ip4[0])<<40 | uint64(ip4[1])<<32 | uint64(ip4[2])<<24 | uint64(ip4[3])<<16 | uint64(port)
}

// NewScanner creates a new scanner
func NewScanner(config *types.ScanConfig) (*Scanner, error) {
	// Create transport configuration
	transportConfig := &transport.TransportConfig{
		SourceIP:      config.SourceIP,
		Interface:     config.Interface,
		SendBatchSize: config.SendBatch,
		RecvBatchSize: config.RecvBatch,
		RingSize:      config.RingSize,
		TimeoutMS:     config.TimeoutMS,
	}

	// Detect and create best available transport
	transport.CheckCapabilities()

	trans, err := transport.DetectBestTransport(transportConfig)
	if err != nil {
		return nil, fmt.Errorf("no transport available: %w", err)
	}

	// Create packet forger
	forger := packet.NewForger(config.SourceIP)

	// Create rate limiter
	jitterMax := time.Duration(config.JitterMaxMS) * time.Millisecond
	limiter := NewJitteredLimiter(config.RateLimit, 0, jitterMax)

	// Create source port pool if randomization enabled
	var srcPortPool *randomizer.SourcePortPool
	if config.RandomizeSourcePort {
		srcPortPool = randomizer.NewSourcePortPool(config.SourcePortMin, config.SourcePortMax)
	}

	batchSize := config.SendBatch
	if batchSize <= 0 {
		batchSize = defaultBatchSize
	}

	return &Scanner{
		config:      config,
		forger:      forger,
		transport:   trans,
		limiter:     limiter,
		srcPortPool: srcPortPool,
		results:     make(chan *types.ScanResult, 1000),
		senderDone:  make(chan struct{}),
		pending:     make(map[uint16]*pendingScan),
		seen:        make(map[uint64]struct{}),
		packetBatch: make([]*transport.Packet, 0, batchSize),
	}, nil
}

// Scan performs the port scan
func (s *Scanner) Scan(ctx context.Context) (<-chan *types.ScanResult, error) {
	// Start receiver goroutine first
	go s.receiver(ctx)

	// Give receiver time to start
	time.Sleep(50 * time.Millisecond)

	// Start sender goroutine
	go s.sender(ctx)

	return s.results, nil
}

func (s *Scanner) sender(ctx context.Context) {
	seed := s.config.Seed
	resumeFrom := s.config.ResumeFrom
	batchSize := int(s.config.IPBatchSize)

	// Create pair randomizer (either from IP list or CIDR)
	var pairRand *randomizer.PairRandomizer
	var err error
	if len(s.config.TargetIPs) > 0 {
		pairRand, err = randomizer.NewPairRandomizerFromIPs(
			s.config.TargetIPs, s.config.Ports, batchSize, seed)
	} else {
		pairRand, err = randomizer.NewPairRandomizerFromCIDR(
			s.config.CIDR, s.config.Ports, batchSize, seed)
	}
	if err != nil {
		log.Printf("Failed to create pair randomizer: %v", err)
		close(s.senderDone)
		return
	}

	s.totalScans = pairRand.Count()

	// Resume: O(1) jump to the right batch
	if resumeFrom > 0 {
		pairRand.SkipTo(resumeFrom)
	}
	packetIndex := resumeFrom

	for {
		select {
		case <-ctx.Done():
			s.flushSendBatch()
			time.Sleep(time.Duration(s.config.TimeoutMS) * time.Millisecond)
			close(s.senderDone)
			return
		default:
		}

		pair, ok := pairRand.Next()
		if !ok {
			// Flush remaining packets
			s.flushSendBatch()
			// Done sending, wait for all responses or timeouts
			timeout := time.Duration(s.config.TimeoutMS) * time.Millisecond
			time.Sleep(timeout + 500*time.Millisecond)
			close(s.senderDone)
			return
		}

		// Update packetsSent before sending
		s.packetsSent.Store(int64(packetIndex))

		// Rate limiting with jitter
		if err := s.limiter.Wait(ctx); err != nil {
			s.flushSendBatch()
			time.Sleep(time.Duration(s.config.TimeoutMS) * time.Millisecond)
			close(s.senderDone)
			return
		}

		// Get source port
		var srcPort uint16
		if s.config.RandomizeSourcePort {
			srcPort = s.srcPortPool.GetRandomPort()
		} else {
			srcPort = s.config.SourcePort
		}

		// Send SYN packet (batched)
		if err := s.sendSYNBatched(pair.IP, pair.Port, srcPort); err != nil {
			s.handleSendError(err, pair.IP, pair.Port)
			s.markDone()
		}

		packetIndex++
	}
}

func (s *Scanner) sendSYNBatched(dstIP net.IP, dstPort, srcPort uint16) error {
	// Forge SYN packet
	pktData, err := s.forger.ForgeSYN(srcPort, dstIP, dstPort)
	if err != nil {
		return err
	}

	// Track this pending scan
	s.pendingLock.Lock()
	s.pending[srcPort] = &pendingScan{
		ip:       dstIP,
		port:     dstPort,
		sendTime: time.Now(),
	}
	s.pendingLock.Unlock()

	// Create transport packet
	pkt := &transport.Packet{
		Data:    pktData,
		DstIP:   dstIP,
		DstPort: dstPort,
		SrcPort: srcPort,
		Length:  len(pktData),
	}

	// Add to batch
	s.packetBatch = append(s.packetBatch, pkt)

	batchSize := s.config.SendBatch
	if batchSize <= 0 {
		batchSize = defaultBatchSize
	}
	if len(s.packetBatch) >= batchSize {
		return s.flushSendBatch()
	}

	return nil
}

func (s *Scanner) flushSendBatch() error {
	if len(s.packetBatch) == 0 {
		return nil
	}

	// Send batch via transport
	_, err := s.transport.Send(s.packetBatch)

	// Clear batch for reuse
	s.packetBatch = s.packetBatch[:0]

	return err
}

func (s *Scanner) receiver(ctx context.Context) {
	defer close(s.results)

	timeout := time.Duration(s.config.TimeoutMS) * time.Millisecond
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.senderDone:
			// Sender finished; final timeout sweep then exit
			s.checkTimeouts(timeout)
			return
		default:
		}

		select {
		case <-ticker.C:
			s.checkTimeouts(timeout)
		default:
		}

		// Receive packets via transport
		packets, err := s.transport.Receive(ctx)
		if err != nil {
			log.Printf("Error receiving packets: %v", err)
			continue
		}

		if len(packets) == 0 {
			time.Sleep(10 * time.Millisecond)
			continue
		}

		// Process all received packets
		for _, pkt := range packets {
			s.processTransportPacket(pkt, ctx)
		}
	}
}

func (s *Scanner) processTransportPacket(pkt *transport.ReceivedPacket, ctx context.Context) {
	// Check if this is a response to one of our scans (using destination port as our source port)
	s.pendingLock.Lock()
	pending, exists := s.pending[pkt.DstPort]
	if exists {
		delete(s.pending, pkt.DstPort)
	}
	s.pendingLock.Unlock()

	if !exists {
		return // Not our scan
	}

	// Verify it's from the expected IP
	if !net.IP(pkt.SrcIP).Equal(pending.ip) {
		return
	}

	// Dedup: skip if we already reported this ip:port (source port reuse can cause false matches)
	key := portKey(pkt.SrcIP, pkt.SrcPort)
	s.seenLock.Lock()
	if _, dup := s.seen[key]; dup {
		s.seenLock.Unlock()
		return
	}
	s.seen[key] = struct{}{}
	s.seenLock.Unlock()

	// Calculate RTT
	rtt := time.Since(pending.sendTime)

	// Determine port state from TCP flags
	var state types.PortState
	if pkt.Flags&0x12 == 0x12 { // SYN+ACK
		state = types.PortOpen
	} else if pkt.Flags&0x04 != 0 { // RST
		state = types.PortClosed
	} else {
		state = types.PortFiltered
	}

	// Create result
	result := &types.ScanResult{
		IP:        net.IP(pkt.SrcIP).String(),
		Port:      int(pkt.SrcPort),
		State:     state,
		Timestamp: time.Now(),
		RTT:       rtt,
	}

	// Release source port back to pool
	if s.srcPortPool != nil {
		s.srcPortPool.ReleasePort(pkt.DstPort)
	}

	// Send result to channel
	select {
	case s.results <- result:
	case <-ctx.Done():
		return
	default:
		// Channel closed, stop
		return
	}

	s.markDone()
}

func (s *Scanner) markDone() {
	s.doneLock.Lock()
	s.doneScans++
	s.doneLock.Unlock()
}

func (s *Scanner) handleSendError(err error, ip net.IP, port uint16) {
	s.errorLock.Lock()
	defer s.errorLock.Unlock()

	s.sendErrors++

	// Check if it's a "no buffer space available" error
	errStr := err.Error()
	if strings.Contains(errStr, "no buffer space available") {
		s.bufferErrors++

		// Show warning only once
		if !s.bufferWarnShown {
			log.Printf("WARNING: Buffer space exhausted - rate limit may be too high")
			log.Printf("WARNING: Consider reducing --rate-limit or increasing system buffers")
			s.bufferWarnShown = true
		}

		// Add a small sleep to help recover from buffer exhaustion
		time.Sleep(10 * time.Millisecond)
	} else {
		// Log other errors (but only if verbose or critical)
		verbose := os.Getenv("VERBOSE") != ""
		if verbose {
			log.Printf("Failed to send SYN to %s:%d: %v", ip, port, err)
		}
	}
}

func (s *Scanner) checkTimeouts(timeout time.Duration) {
	now := time.Now()
	s.pendingLock.Lock()
	defer s.pendingLock.Unlock()

	for srcPort, pending := range s.pending {
		if now.Sub(pending.sendTime) > timeout {
			// Timeout - port is filtered
			result := &types.ScanResult{
				IP:        pending.ip.String(),
				Port:      int(pending.port),
				State:     types.PortFiltered,
				Timestamp: now,
				RTT:       timeout,
			}

			// Release source port
			if s.srcPortPool != nil {
				s.srcPortPool.ReleasePort(srcPort)
			}

			delete(s.pending, srcPort)

			// Send result (non-blocking)
			select {
			case s.results <- result:
			default:
				// Channel might be closed
			}

			s.markDone()
		}
	}
}

// Close closes the scanner resources
func (s *Scanner) Close() error {
	// Print error summary if there were send errors
	s.errorLock.Lock()
	if s.sendErrors > 0 {
		log.Printf("Send errors: %d total (%d buffer exhaustion)", s.sendErrors, s.bufferErrors)
		if s.bufferErrors > 0 {
			log.Printf("Tip: Reduce --rate-limit or increase system buffers with:")
			log.Printf("  sudo sysctl -w net.core.wmem_max=12582912")
			log.Printf("  sudo sysctl -w net.core.rmem_max=12582912")
		}
	}
	s.errorLock.Unlock()

	return s.transport.Close()
}

// Progress returns how many packets were sent vs total
func (s *Scanner) Progress() (done, total int) {
	return int(s.packetsSent.Load()), s.totalScans
}

// TransportMethod returns the name of the transport method in use
func (s *Scanner) TransportMethod() string {
	return s.transport.Method().String()
}
