package grab

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
)

// WorkerPool manages a pool of workers for service scanning
// Architecture inspired by zgrab2 with optimizations to reduce the memory footprint
type WorkerPool struct {
	numWorkers    int
	inputQueue    chan ScanRequest
	outputQueue   chan ScanResult
	workerWg      sync.WaitGroup
	done          chan struct{}
	probeDB       *ProbeDB
	totalScanned  uint64
	totalSuccess  uint64
	totalFailures uint64
	totalTimeouts uint64

	// Auto-tuning
	tuner           *WorkerTuner
	resourceMonitor *VPSResourceMonitor
	adaptiveConfig  *AdaptiveConfig
	autoTune        bool

	// Dynamic worker management
	workersMu      sync.RWMutex
	activeWorkers  int
	workerControls []chan struct{} // One channel per worker to stop it
}

// ScanRequest represents a scan request
type ScanRequest struct {
	Host          string
	Port          int
	ProbeTimeout  time.Duration
	Intensity     int
	GlobalTimeout time.Duration
	Debug         bool
	ResultChan    chan<- ScanResult // Optional channel to receive the result directly
}

// ScanResult represents the result of a scan
type ScanResult struct {
	Host        string
	Port        int
	Result      *ServiceResult
	Error       error
	TimeoutType string // "network", "global", "probe", "" (no timeout)
}

// WorkerPoolConfig configures the worker pool
type WorkerPoolConfig struct {
	NumWorkers    int           // Number of workers (default: CPU * 4)
	QueueSize     int           // Queue size (default: NumWorkers * 4)
	ProbeTimeout  time.Duration // Timeout per probe (default: 5s)
	Intensity     int           // Scan intensity (default: 7)
	GlobalTimeout time.Duration // Global timeout per scan (default: 20s)
	Debug         bool
	AutoTune      bool // Enable auto-tuning (recommended for VPS)
}

// DefaultWorkerPoolConfig returns a default config
func DefaultWorkerPoolConfig() *WorkerPoolConfig {
	// Use GetRecommendedWorkers() to compute based on resources
	numWorkers := GetRecommendedWorkers()

	return &WorkerPoolConfig{
		NumWorkers:    numWorkers,
		QueueSize:     numWorkers * 4,
		ProbeTimeout:  5 * time.Second,
		Intensity:     7,
		GlobalTimeout: 20 * time.Second,
		Debug:         false,
		AutoTune:      true, // Enabled by default
	}
}

// NewWorkerPool creates a new worker pool
func NewWorkerPool(config *WorkerPoolConfig) (*WorkerPool, error) {
	if config == nil {
		config = DefaultWorkerPoolConfig()
	}

	// Load the ProbeDB only once (singleton already handled by getProbeDB)
	db, err := getProbeDB()
	if err != nil {
		return nil, fmt.Errorf("failed to load probes: %w", err)
	}

	pool := &WorkerPool{
		numWorkers:      config.NumWorkers,
		inputQueue:      make(chan ScanRequest, config.QueueSize),
		outputQueue:     make(chan ScanResult, config.QueueSize),
		done:            make(chan struct{}),
		probeDB:         db,
		autoTune:        config.AutoTune,
		tuner:           NewWorkerTuner(config.NumWorkers),
		resourceMonitor: NewVPSResourceMonitor(),
		adaptiveConfig:  DefaultAdaptiveConfig(),
		activeWorkers:   config.NumWorkers,
		workerControls:  make([]chan struct{}, 0, config.NumWorkers),
	}

	// Print the initial resources
	PrintResourceStats()

	// Start the workers
	pool.workerWg.Add(config.NumWorkers)
	for i := 0; i < config.NumWorkers; i++ {
		stopChan := make(chan struct{})
		pool.workerControls = append(pool.workerControls, stopChan)
		go pool.worker(i, stopChan)
	}

	// Start auto-tune monitoring if enabled
	if pool.autoTune {
		go pool.autoTuneLoop()
	}

	return pool, nil
}

// worker is the function executed by each worker
func (p *WorkerPool) worker(id int, stopChan chan struct{}) {
	defer p.workerWg.Done()

	// Each worker reuses the same context to minimize allocations
	for {
		select {
		case <-p.done:
			return
		case <-stopChan:
			// This specific worker must stop
			return
		case req, ok := <-p.inputQueue:
			if !ok {
				return // Queue closed
			}

			// IMPROVEMENT: Adapt the timeout based on the service type (if already known)
			globalTimeout := req.GlobalTimeout
			if globalTimeout == 0 {
				globalTimeout = 20 * time.Second // Default fallback
			}

			// Perform the scan with a global timeout
			ctx, cancel := context.WithTimeout(context.Background(), globalTimeout)

			// Channel to receive the result
			resultChan := make(chan ScanResult, 1)

			// Run the scan in a goroutine to honor the global timeout
			go func() {
				result, err := p.probeDB.ScanPortAuto(req.Host, req.Port, req.ProbeTimeout, req.Intensity)

				res := ScanResult{
					Host:   req.Host,
					Port:   req.Port,
					Result: result,
					Error:  err,
				}

				// Use select to avoid blocking forever if pool is shutting down
				select {
				case resultChan <- res:
				case <-p.done:
				}
			}()

			// Wait for the result or the timeout
			select {
			case res := <-resultChan:
				atomic.AddUint64(&p.totalScanned, 1)
				isTimeout := false
				isError := false

				// IMPROVEMENT: Detect the timeout/error type
				if res.Error == nil {
					atomic.AddUint64(&p.totalSuccess, 1)
					res.TimeoutType = "" // No timeout
				} else {
					atomic.AddUint64(&p.totalFailures, 1)
					isError = true

					// Classify the error type
					errMsg := res.Error.Error()
					if strings.Contains(errMsg, "timeout") || strings.Contains(errMsg, "i/o timeout") {
						res.TimeoutType = "network" // Network timeout (real saturation)
						isTimeout = true
						atomic.AddUint64(&p.totalTimeouts, 1)
					} else if strings.Contains(errMsg, "connection reset") {
						res.TimeoutType = "" // Not a timeout, just a closed connection
						// Blacklist disabled (scanmap/blacklist dependency removed)
						// bl := blacklist.GetBlacklist()
						// bl.RecordConnectionReset(req.Host, req.Port)
					} else if strings.Contains(errMsg, "connection refused") {
						res.TimeoutType = "" // Port closed, not a timeout
					} else {
						res.TimeoutType = "" // Other error
					}
				}

				// IMPROVEMENT: Only penalize autotune for network timeouts
				if p.autoTune {
					p.tuner.RecordScan(isTimeout, isError)
				}

				// Send the result to the right recipient
				if req.ResultChan != nil {
					// Send directly on the provided channel
					select {
					case req.ResultChan <- res:
					case <-p.done:
						cancel()
						return
					}
				} else {
					// Send on the global queue
					select {
					case p.outputQueue <- res:
					case <-p.done:
						cancel()
						return
					}
				}
			case <-ctx.Done():
				// IMPROVEMENT: Global timeout (not necessarily a network problem)
				atomic.AddUint64(&p.totalScanned, 1)
				atomic.AddUint64(&p.totalFailures, 1)
				atomic.AddUint64(&p.totalTimeouts, 1)

				// Global timeout = scan too slow, but not necessarily network saturation
				// Do not penalize autotune as harshly as a real network timeout
				if p.autoTune {
					p.tuner.RecordScan(false, true) // Count as an error, not a timeout
				}

				timeoutResult := ScanResult{
					Host:        req.Host,
					Port:        req.Port,
					Result:      nil,
					Error:       fmt.Errorf("scan timeout after %v", req.GlobalTimeout),
					TimeoutType: "global", // Global timeout (scan too long)
				}

				// Send the result to the right recipient
				if req.ResultChan != nil {
					select {
					case req.ResultChan <- timeoutResult:
					case <-p.done:
						cancel()
						return
					}
				} else {
					select {
					case p.outputQueue <- timeoutResult:
					case <-p.done:
						cancel()
						return
					}
				}
			case <-p.done:
				cancel()
				return
			}

			cancel()
		}
	}
}

// Submit submits a scan request to the pool (blocking with timeout)
func (p *WorkerPool) Submit(req ScanRequest) error {
	timer := time.NewTimer(30 * time.Second)
	defer timer.Stop()

	select {
	case p.inputQueue <- req:
		return nil
	case <-timer.C:
		return fmt.Errorf("input queue full after 30s (%d/%d)", len(p.inputQueue), cap(p.inputQueue))
	case <-p.done:
		return fmt.Errorf("worker pool is closed")
	}
}

// Results returns the results channel (read-only)
func (p *WorkerPool) Results() <-chan ScanResult {
	return p.outputQueue
}

// Close shuts down the worker pool cleanly
func (p *WorkerPool) Close() {
	close(p.done)
	close(p.inputQueue)
	p.workerWg.Wait()
	// Note: outputQueue is intentionally NOT closed here.
	// Goroutines spawned by workers (for ScanPortAuto) may still be draining
	// and attempting to write to resultChan/outputQueue. Closing would cause
	// a panic ("send on closed channel"). The channel will be GC'd when
	// all references are released.
}

// Stats returns the pool statistics
func (p *WorkerPool) Stats() (scanned, success, failures uint64) {
	return atomic.LoadUint64(&p.totalScanned),
		atomic.LoadUint64(&p.totalSuccess),
		atomic.LoadUint64(&p.totalFailures)
}

// DetailedStats returns detailed statistics
func (p *WorkerPool) DetailedStats() map[string]interface{} {
	scanned := atomic.LoadUint64(&p.totalScanned)
	success := atomic.LoadUint64(&p.totalSuccess)
	failures := atomic.LoadUint64(&p.totalFailures)
	timeouts := atomic.LoadUint64(&p.totalTimeouts)

	successRate := 0.0
	if scanned > 0 {
		successRate = float64(success) / float64(scanned) * 100
	}

	timeoutRate := 0.0
	if scanned > 0 {
		timeoutRate = float64(timeouts) / float64(scanned) * 100
	}

	p.workersMu.RLock()
	activeWorkers := p.activeWorkers
	p.workersMu.RUnlock()

	return map[string]interface{}{
		"workers":      activeWorkers,
		"scanned":      scanned,
		"success":      success,
		"failures":     failures,
		"timeouts":     timeouts,
		"success_rate": successRate,
		"timeout_rate": timeoutRate,
		"queue_input":  len(p.inputQueue),
		"queue_output": len(p.outputQueue),
		"auto_tune":    p.autoTune,
		"adjustments":  p.tuner.adjustments,
	}
}

// adjustWorkers dynamically adjusts the number of workers
func (p *WorkerPool) adjustWorkers(targetWorkers int) {
	p.workersMu.Lock()
	defer p.workersMu.Unlock()

	current := p.activeWorkers

	if targetWorkers == current {
		return
	}

	if targetWorkers > current {
		// Add workers
		numToAdd := targetWorkers - current
		log.Info().
			Int("adding", numToAdd).
			Int("from", current).
			Int("to", targetWorkers).
			Msg("Adding workers")

		for i := 0; i < numToAdd; i++ {
			stopChan := make(chan struct{})
			p.workerControls = append(p.workerControls, stopChan)
			p.workerWg.Add(1)
			go p.worker(current+i, stopChan)
		}

		p.activeWorkers = targetWorkers
	} else {
		// Remove workers
		numToRemove := current - targetWorkers
		log.Info().
			Int("removing", numToRemove).
			Int("from", current).
			Int("to", targetWorkers).
			Msg("Removing workers")

		// Close the control channels of the last workers
		for i := 0; i < numToRemove && len(p.workerControls) > 0; i++ {
			lastIdx := len(p.workerControls) - 1
			close(p.workerControls[lastIdx])
			p.workerControls = p.workerControls[:lastIdx]
		}

		p.activeWorkers = targetWorkers
	}
}

var poolLog string

// autoTuneLoop monitors and adjusts the number of workers
func (p *WorkerPool) autoTuneLoop() {
	ticker := time.NewTicker(10 * time.Second) // Check every 10s for responsiveness
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// IMPROVEMENT: Actually implement throttling
			shouldThrottle := p.resourceMonitor.ShouldThrottle()
			if shouldThrottle {
				log.Warn().Msg("TUNE: Resource throttling active - Pausing submissions")
				// Aggressively reduce workers if throttling is active
				p.workersMu.RLock()
				currentWorkers := p.activeWorkers
				p.workersMu.RUnlock()

				targetWorkers := currentWorkers / 2 // Reduce by 50%
				if targetWorkers < p.tuner.minWorkers {
					targetWorkers = p.tuner.minWorkers
				}

				if targetWorkers != currentWorkers {
					log.Info().
						Int("from", currentWorkers).
						Int("to", targetWorkers).
						Msg("TUNE: Resource overload - Force reducing workers")
					p.adjustWorkers(targetWorkers)
				}

				// Pause to let resources free up
				time.Sleep(2 * time.Second)
				continue
			}

			// Print the stats with goroutine count (enrichment disabled)
			stats := p.DetailedStats()
			poolTmp := fmt.Sprintf("POOL: Workers=%d Scanned=%d Success=%.1f%% Timeout=%.1f%% Queue=%d/%d",
				stats["workers"], stats["scanned"], stats["success_rate"],
				stats["timeout_rate"], stats["queue_input"], stats["queue_output"])
			if poolLog != poolTmp {
				log.Print(poolTmp)
				poolLog = poolTmp
			}
			// Dynamically adjust the number of workers
			if newWorkers, shouldChange := p.tuner.ShouldAdjust(); shouldChange {
				p.adjustWorkers(newWorkers)
			}

		case <-p.done:
			return
		}
	}
}

// ScanBatch scans a batch of hosts in parallel and returns all the results.
// Uses per-request ResultChan to avoid reading from the shared outputQueue,
// which prevents mixing results between concurrent batches and goroutine leaks.
func (p *WorkerPool) ScanBatch(requests []ScanRequest) ([]ScanResult, error) {
	if len(requests) == 0 {
		return nil, nil
	}

	// Create a shared result channel for this batch
	batchResults := make(chan ScanResult, len(requests))

	// Submit all requests with the shared result channel
	for i := range requests {
		requests[i].ResultChan = batchResults
		if err := p.Submit(requests[i]); err != nil {
			return nil, err
		}
	}

	// Collect results with timeout
	results := make([]ScanResult, 0, len(requests))
	timeout := time.NewTimer(30 * time.Second)
	defer timeout.Stop()

	for len(results) < len(requests) {
		select {
		case res := <-batchResults:
			results = append(results, res)
		case <-timeout.C:
			return results, fmt.Errorf("batch scan timeout: got %d/%d results", len(results), len(requests))
		case <-p.done:
			return results, fmt.Errorf("worker pool closed during batch scan")
		}
	}

	return results, nil
}
