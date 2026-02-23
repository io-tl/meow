package transport

import (
	"context"
	"errors"
	"net"
	"sync"
	"syscall"
	"time"
)

// ConnectTransport implements Transport using standard TCP connect()
// Optimized for high-performance with massive parallelization
type ConnectTransport struct {
	config  *TransportConfig
	timeout time.Duration

	// Worker pool for parallel connects
	workers      int
	jobQueue     chan *connectJob
	resultQueue  chan *ReceivedPacket
	workersDone  chan struct{}
	workersGroup sync.WaitGroup

	// Shutdown coordination
	ctx    context.Context
	cancel context.CancelFunc
}

type connectJob struct {
	packet *Packet
}

// NewConnectTransport creates a new connect-based transport
func NewConnectTransport(config *TransportConfig) (Transport, error) {
	timeout := time.Duration(config.TimeoutMS) * time.Millisecond
	if timeout == 0 {
		timeout = 1 * time.Second // Reduced default timeout
	}

	// Massive parallelization for performance
	// Adjust based on system limits (ulimit -n)
	workers := 5000

	ctx, cancel := context.WithCancel(context.Background())

	t := &ConnectTransport{
		config:      config,
		timeout:     timeout,
		workers:     workers,
		jobQueue:    make(chan *connectJob, workers*2),
		resultQueue: make(chan *ReceivedPacket, 1000),
		workersDone: make(chan struct{}),
		ctx:         ctx,
		cancel:      cancel,
	}

	// Start worker pool
	t.startWorkers()

	return t, nil
}

// startWorkers initializes the worker pool
func (c *ConnectTransport) startWorkers() {
	for i := 0; i < c.workers; i++ {
		c.workersGroup.Add(1)
		go c.worker()
	}

	// Start result collector
	go c.resultCollector()
}

func (c *ConnectTransport) Method() TransportMethod {
	return TransportConnect
}

func (c *ConnectTransport) Send(packets []*Packet) (int, error) {
	if len(packets) == 0 {
		return 0, nil
	}

	// Queue all packets for workers to process
	sent := 0
	for _, pkt := range packets {
		select {
		case c.jobQueue <- &connectJob{packet: pkt}:
			sent++
		case <-c.ctx.Done():
			return sent, c.ctx.Err()
		}
	}

	return sent, nil
}

// worker processes connection jobs from the queue
func (c *ConnectTransport) worker() {
	defer c.workersGroup.Done()
	defer func() {
		// Recover from any panic to avoid stack traces on shutdown
		if r := recover(); r != nil {
			// Silently ignore panics during shutdown
		}
	}()

	for {
		select {
		case job := <-c.jobQueue:
			if job == nil {
				return
			}

			// Check if we're shutting down before processing
			select {
			case <-c.ctx.Done():
				return
			default:
			}

			result := c.tryConnect(job.packet)
			if result != nil {
				select {
				case c.resultQueue <- result:
				case <-c.ctx.Done():
					return
				}
			}
		case <-c.ctx.Done():
			return
		}
	}
}

// resultCollector aggregates results from workers
func (c *ConnectTransport) resultCollector() {
	// This goroutine stays alive for the lifetime of the transport
	<-c.ctx.Done()
	close(c.workersDone)
}

func (c *ConnectTransport) tryConnect(pkt *Packet) *ReceivedPacket {
	// Create TCP address
	addr := &net.TCPAddr{
		IP:   pkt.DstIP,
		Port: int(pkt.DstPort),
	}

	// Use Dialer with context for cancellable dial
	dialer := &net.Dialer{
		Timeout: c.timeout,
	}

	conn, err := dialer.DialContext(c.ctx, "tcp", addr.String())

	// Create result based on connection outcome
	result := &ReceivedPacket{
		SrcIP:     pkt.DstIP,
		SrcPort:   pkt.DstPort,
		DstPort:   pkt.SrcPort,
		Timestamp: time.Now(),
	}

	if err == nil {
		// Connection successful - port is open
		conn.Close()
		result.Flags = 0x12 // SYN+ACK
		return result
	}

	// Check error type to determine port state
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		// Timeout - port is filtered
		result.Flags = 0x00 // No response (filtered)
		return result
	}

	// Check for connection refused (port closed)
	// Use errors.Is to correctly unwrap through *net.OpError, *os.SyscallError, etc.
	if errors.Is(err, syscall.ECONNREFUSED) {
		result.Flags = 0x04 // RST
		return result
	}

	// Other errors - treat as filtered
	result.Flags = 0x00
	return result
}

func (c *ConnectTransport) Receive(ctx context.Context) ([]*ReceivedPacket, error) {
	// Non-blocking receive from result queue
	var results []*ReceivedPacket

	// Drain up to 100 results at a time
	for i := 0; i < 100; i++ {
		select {
		case result := <-c.resultQueue:
			if result != nil {
				results = append(results, result)
			}
		default:
			// No more results available
			return results, nil
		}
	}

	return results, nil
}

func (c *ConnectTransport) Close() error {
	// Signal shutdown to all workers
	c.cancel()

	// Drain remaining jobs to unblock any senders
	go func() {
		for range c.jobQueue {
			// Discard
		}
	}()

	// Give workers a moment to finish current operations
	time.Sleep(50 * time.Millisecond)

	// Close job queue to unblock workers
	close(c.jobQueue)

	// Wait for all workers to finish (with timeout to avoid hanging)
	done := make(chan struct{})
	go func() {
		c.workersGroup.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All workers finished
	case <-time.After(1 * time.Second):
		// Timeout - workers are taking too long, force exit
	}

	// Wait for result collector
	select {
	case <-c.workersDone:
	case <-time.After(100 * time.Millisecond):
	}

	// Close result queue
	close(c.resultQueue)

	return nil
}

func (c *ConnectTransport) GetCapabilities() Capabilities {
	return Capabilities{
		SupportsSYNScan:          false, // Full 3-way handshake, not true SYN scan
		SupportsCustomSourcePort: false, // Usually requires privileges
		SupportsRawPackets:       false,
		RequiresRoot:             false,
		MaxPacketsPerSecond:      50000, // Optimized: ~50K PPS with 5000 workers
	}
}

// IsPortOpen is a helper to determine if a port is open from flags
func IsPortOpen(flags uint8) bool {
	return flags&0x12 == 0x12 // SYN+ACK
}

// IsPortClosed is a helper to determine if a port is closed from flags
func IsPortClosed(flags uint8) bool {
	return flags&0x04 != 0 // RST
}

// IsPortFiltered is a helper to determine if a port is filtered from flags
func IsPortFiltered(flags uint8) bool {
	return flags == 0x00 // No response
}
