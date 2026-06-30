package grab

import (
	"fmt"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"

	"time"

	"github.com/rs/zerolog/log"
)

// MetricsSnapshot represents a snapshot of metrics at a given instant T
type MetricsSnapshot struct {
	Timestamp   time.Time
	Scans       uint64
	Timeouts    uint64
	Errors      uint64
	TimeoutRate float64
	Workers     int
	Adjustment  string // "increase", "decrease", "stable"
}

// WorkerTuner automatically adjusts the number of workers based on performance
type WorkerTuner struct {
	// Metrics
	totalScans    uint64
	totalTimeouts uint64
	totalErrors   uint64
	lastCheck     time.Time

	// Config
	minWorkers    int
	maxWorkers    int
	targetTimeout float64 // Target timeout rate (e.g.: 5%)

	// State
	currentWorkers          int
	adjustments             int
	lastAdjustmentDir       int // -1 = decrease, 0 = none, +1 = increase
	consecutiveOscillations int // Oscillation counter

	// History (circular buffer of the last 10 periods)
	history     []MetricsSnapshot
	historyIdx  int
	historySize int

	// Thread-safety
	mu sync.RWMutex
}

// NewWorkerTuner creates an automatic tuner
func NewWorkerTuner(initialWorkers int) *WorkerTuner {
	numCPU := runtime.NumCPU()

	// Higher minimum for modern VPS (at least 20 workers even with few CPUs)
	minWorkers := numCPU * 2
	if minWorkers < 20 {
		minWorkers = 20
	}

	return &WorkerTuner{
		minWorkers:              minWorkers,     // Minimum: 20 or 2*CPU (aggressive for I/O bound)
		maxWorkers:              300,            // Maximum: 300 workers (default from config)
		targetTimeout:           0.05,           // 5% timeout acceptable
		currentWorkers:          initialWorkers, // Start with the recommended number
		lastCheck:               time.Now(),
		lastAdjustmentDir:       0,
		consecutiveOscillations: 0,
		history:                 make([]MetricsSnapshot, 10),
		historyIdx:              0,
		historySize:             0,
	}
}

// RecordScan records the result of a scan
func (wt *WorkerTuner) RecordScan(timedout bool, errored bool) {
	scans := atomic.AddUint64(&wt.totalScans, 1)
	if timedout {
		timeouts := atomic.AddUint64(&wt.totalTimeouts, 1)
		if scans%10 == 0 { // Log every 10 scans
			log.Debug().
				Uint64("scan_count", scans).
				Uint64("timeouts", timeouts).
				Float64("timeout_rate", float64(timeouts)/float64(scans)*100).
				Msg("Tune: Recorded scan batch")
		}
	}
	if errored {
		atomic.AddUint64(&wt.totalErrors, 1)
	}
}

// addSnapshot adds a snapshot to the history (circular buffer)
func (wt *WorkerTuner) addSnapshot(snapshot MetricsSnapshot) {
	wt.mu.Lock()
	defer wt.mu.Unlock()

	wt.history[wt.historyIdx] = snapshot
	wt.historyIdx = (wt.historyIdx + 1) % 10
	if wt.historySize < 10 {
		wt.historySize++
	}
}

// GetHistory returns the metrics history
func (wt *WorkerTuner) GetHistory() []MetricsSnapshot {
	wt.mu.RLock()
	defer wt.mu.RUnlock()

	result := make([]MetricsSnapshot, wt.historySize)
	for i := 0; i < wt.historySize; i++ {
		idx := (wt.historyIdx - wt.historySize + i + 10) % 10
		result[i] = wt.history[idx]
	}
	return result
}

// detectOscillation detects whether we are oscillating (increasing then decreasing repeatedly)
func (wt *WorkerTuner) detectOscillation(newDir int) bool {
	wt.mu.Lock()
	defer wt.mu.Unlock()

	// If the direction changes, it's a potential oscillation
	if wt.lastAdjustmentDir != 0 && newDir != 0 && wt.lastAdjustmentDir != newDir {
		wt.consecutiveOscillations++
		wt.lastAdjustmentDir = newDir
		return wt.consecutiveOscillations >= 3 // 3 oscillations = problem
	}

	wt.lastAdjustmentDir = newDir
	if newDir == 0 {
		wt.consecutiveOscillations = 0 // Reset if stable
	}
	return false
}

// ShouldAdjust checks whether we should adjust the workers (IMPROVEMENT: gradual adjustment)
func (wt *WorkerTuner) ShouldAdjust() (newWorkers int, shouldChange bool) {
	// Check at least every 10 seconds (increased responsiveness)
	wt.mu.RLock()
	timeSince := time.Since(wt.lastCheck)
	wt.mu.RUnlock()

	if timeSince < 10*time.Second {
		return wt.currentWorkers, false
	}

	scans := atomic.LoadUint64(&wt.totalScans)
	timeouts := atomic.LoadUint64(&wt.totalTimeouts)
	errors := atomic.LoadUint64(&wt.totalErrors)

	// Lower the threshold to 10 scans to react faster
	if scans < 10 {
		return wt.currentWorkers, false
	}

	timeoutRate := float64(timeouts) / float64(scans)

	// Create a snapshot before resetting the counters
	snapshot := MetricsSnapshot{
		Timestamp:   time.Now(),
		Scans:       scans,
		Timeouts:    timeouts,
		Errors:      errors,
		TimeoutRate: timeoutRate,
		Workers:     wt.currentWorkers,
		Adjustment:  "stable",
	}

	// Reset the counters
	atomic.StoreUint64(&wt.totalScans, 0)
	atomic.StoreUint64(&wt.totalTimeouts, 0)
	atomic.StoreUint64(&wt.totalErrors, 0)
	wt.mu.Lock()
	wt.lastCheck = time.Now()
	wt.mu.Unlock()

	adjustmentDir := 0

	// IMPROVEMENT 1: GRADUAL reduction instead of aggressive
	if timeoutRate > wt.targetTimeout*2 { // > 10%
		adjustmentDir = -1

		// Detect oscillation
		if wt.detectOscillation(adjustmentDir) {
			log.Info().Int("workers", wt.currentWorkers).Msg("TUNE: Oscillation detected - Stabilizing")
			snapshot.Adjustment = "oscillation-stabilize"
			wt.addSnapshot(snapshot)
			return wt.currentWorkers, false
		}

		// Gradual reduction: -20% per cycle, capped at -50 workers max
		reduction := int(float64(wt.currentWorkers) * 0.20)
		if reduction > 50 {
			reduction = 50
		}
		if reduction < 10 {
			reduction = 10 // At least -10 workers
		}

		newWorkers = wt.currentWorkers - reduction
		if newWorkers < wt.minWorkers {
			newWorkers = wt.minWorkers
		}

		if newWorkers != wt.currentWorkers {
			log.Info().
				Float64("timeout_rate", timeoutRate*100).
				Int("from", wt.currentWorkers).
				Int("to", newWorkers).
				Int("reduction", reduction).
				Msg("TUNE: High timeout rate - Reducing workers")
			wt.currentWorkers = newWorkers
			wt.adjustments++
			snapshot.Adjustment = "decrease"
			wt.addSnapshot(snapshot)
			return newWorkers, true
		}
	} else if timeoutRate < wt.targetTimeout && wt.currentWorkers < wt.maxWorkers {
		// IMPROVEMENT 2: Adaptive increase based on quality
		adjustmentDir = 1

		// Detect oscillation
		if wt.detectOscillation(adjustmentDir) {
			log.Info().Int("workers", wt.currentWorkers).Msg("TUNE: Oscillation detected - Stabilizing")
			snapshot.Adjustment = "oscillation-stabilize"
			wt.addSnapshot(snapshot)
			return wt.currentWorkers, false
		}

		increase := 10 // Default: +10 workers

		// If conditions are excellent (< 2.5% timeout), accelerate
		if timeoutRate < wt.targetTimeout/2 {
			increase = 30 // +30 workers
		} else if timeoutRate < wt.targetTimeout*0.75 {
			increase = 20 // +20 workers
		}

		newWorkers = wt.currentWorkers + increase
		if newWorkers > wt.maxWorkers {
			newWorkers = wt.maxWorkers
		}

		if newWorkers != wt.currentWorkers {
			log.Info().
				Float64("timeout_rate", timeoutRate*100).
				Int("from", wt.currentWorkers).
				Int("to", newWorkers).
				Int("increase", increase).
				Msg("TUNE: Low timeout rate - Increasing workers")
			wt.currentWorkers = newWorkers
			wt.adjustments++
			snapshot.Adjustment = "increase"
			wt.addSnapshot(snapshot)
			return newWorkers, true
		}
	}

	// No change but add the snapshot
	snapshot.Adjustment = "stable"
	wt.addSnapshot(snapshot)
	return wt.currentWorkers, false
}

// GetRecommendedWorkers computes the optimal number of workers based on resources
// IMPROVEMENT: Progressive warm-up instead of aggressive startup
func GetRecommendedWorkers() int {
	numCPU := runtime.NumCPU()

	// Read the memory stats
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	allocMB := m.Alloc / (1024 * 1024)
	sysMB := m.Sys / (1024 * 1024)

	// IMPROVEMENT: PROGRESSIVE WARM-UP
	// Start with a reasonable number and let autotune increase it progressively
	// Benefits:
	// - Avoids the initial load spike (rate-limiting, blacklist)
	// - Quickly detects network/system limits
	// - Reduces the risk of crashing the target
	//
	// Strategy: min(numCPU * 10, 50) to start gently
	// Autotune will increase by +10/+20/+30 per cycle (10s) up to the max

	recommended := numCPU * 10 // E.g.: 8 cores = 80 workers at startup
	if recommended > 50 {
		recommended = 50 // Cap at 50 for warm-up
	}
	if recommended < 20 {
		recommended = 20 // Minimum 20 workers
	}

	// Only if the system is very powerful (16+ cores), start higher
	if numCPU >= 16 {
		recommended = 100 // Powerful systems can start at 100
	}

	warmupTime := (300 - recommended) / 20 * 10 // Estimated time to reach max (300 workers)
	log.Info().
		Int("workers", recommended).
		Int("cpu", numCPU).
		Uint64("alloc_mb", allocMB).
		Uint64("sys_mb", sysMB).
		Int("target", 300).
		Int("eta_seconds", warmupTime).
		Msg("TUNE: Warm-up start")

	return recommended
}

// AdaptiveConfig adjusts timeouts based on the service type
type AdaptiveConfig struct {
	// Adaptive timeouts per protocol
	FastServices   []string // HTTP, SSH: 5s
	MediumServices []string // SMTP, MySQL: 10s
	SlowServices   []string // Custom apps: 30s

	DefaultTimeout time.Duration
	FastTimeout    time.Duration
	MediumTimeout  time.Duration
	SlowTimeout    time.Duration
}

// DefaultAdaptiveConfig returns the default adaptive config
func DefaultAdaptiveConfig() *AdaptiveConfig {
	return &AdaptiveConfig{
		FastServices:   []string{"http", "https", "ssh", "telnet"},
		MediumServices: []string{"smtp", "mysql", "postgresql", "redis", "mongodb"},
		SlowServices:   []string{"ftp", "smb", "custom"},

		DefaultTimeout: 20 * time.Second,
		FastTimeout:    5 * time.Second,
		MediumTimeout:  10 * time.Second,
		SlowTimeout:    30 * time.Second,
	}
}

// GetTimeoutForService returns the timeout suited to the detected service
func (ac *AdaptiveConfig) GetTimeoutForService(service string) time.Duration {
	// Check whether it's a fast service
	if slices.Contains(ac.FastServices, service) {
		return ac.FastTimeout
	}

	// Check whether it's a medium service
	if slices.Contains(ac.MediumServices, service) {
		return ac.MediumTimeout
	}

	// Check whether it's a slow service
	if slices.Contains(ac.SlowServices, service) {
		return ac.SlowTimeout
	}

	return ac.DefaultTimeout
}

// VPSResourceMonitor monitors the VPS resources
type VPSResourceMonitor struct {
	highMemCount int
	totalRAM     uint64 // Total system RAM (detected at startup)
}

// getTotalSystemRAM is defined in sysinfo_linux.go / sysinfo_other.go

// NewVPSResourceMonitor creates a resource monitor
func NewVPSResourceMonitor() *VPSResourceMonitor {
	totalRAM := getTotalSystemRAM()
	log.Info().Uint64("ram_mb", totalRAM).Msg("TUNE: Detected system RAM")

	return &VPSResourceMonitor{
		totalRAM: totalRAM,
	}
}

// CheckResources checks resource usage (IMPROVEMENT: adaptive thresholds)
func (vrm *VPSResourceMonitor) CheckResources() (cpuOK, memOK bool, warnings []string) {
	warnings = make([]string, 0)

	// Check the memory
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	allocMB := m.Alloc / (1024 * 1024)
	sysMB := m.Sys / (1024 * 1024)
	gcPct := float64(m.GCCPUFraction) * 100

	// IMPROVEMENT: Adaptive threshold based on the total system RAM
	memUsagePct := float64(m.Alloc) / float64(m.Sys) * 100

	// Compute the threshold: 85% of the total RAM (instead of a fixed 4GB)
	memThresholdMB := uint64(float64(vrm.totalRAM) * 0.85)

	// Warning if:
	// 1. More than 95% of allocated memory is in use (internal Go pressure)
	// 2. OR if we exceed 85% of the total system RAM
	if memUsagePct > 95 || sysMB > memThresholdMB {
		vrm.highMemCount++
		memOK = false
		warnings = append(warnings,
			fmt.Sprintf("High memory usage: %.1f%% (%dMB / %dMB) - Threshold: %dMB / %dMB total RAM",
				memUsagePct, allocMB, sysMB, memThresholdMB, vrm.totalRAM))
	} else {
		vrm.highMemCount = 0
		memOK = true
	}

	// Alert if GC uses > 10% of the CPU
	if gcPct > 10 {
		warnings = append(warnings,
			fmt.Sprintf("High GC CPU usage: %.1f%%", gcPct))
	}

	// Alert if there are many goroutines
	numGoroutines := runtime.NumGoroutine()
	if numGoroutines > 10000 {
		warnings = append(warnings,
			fmt.Sprintf("High goroutine count: %d", numGoroutines))
	}

	// CPU check (approximate via number of runnable goroutines)
	cpuOK = numGoroutines < 5000

	return cpuOK, memOK, warnings
}

// ShouldThrottle determines whether we should throttle the scans
func (vrm *VPSResourceMonitor) ShouldThrottle() bool {
	cpuOK, memOK, warnings := vrm.CheckResources()

	if len(warnings) > 0 {
		for _, warning := range warnings {
			log.Warn().Str("warning", warning).Msg("TUNE: Resource warning")
		}
	}

	// Throttle if CPU or memory are overloaded for 3 consecutive checks
	if !cpuOK || !memOK {
		if vrm.highMemCount > 3 {
			return true
		}
	}

	return false
}

// PrintResourceStats prints the resource stats
func PrintResourceStats() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	log.Info().
		Uint64("alloc_mb", m.Alloc/(1024*1024)).
		Uint64("sys_mb", m.Sys/(1024*1024)).
		Uint64("gc_mb", m.TotalAlloc/(1024*1024)).
		Msg("TUNE: Memory")
	log.Info().
		Float64("gc_cpu_percent", m.GCCPUFraction*100).
		Uint32("gc_pauses", m.NumGC).
		Uint64("last_pause_ms", m.PauseNs[(m.NumGC+255)%256]/1e6).
		Int("goroutines", runtime.NumGoroutine()).
		Int("cpus", runtime.NumCPU()).
		Msg("TUNE: GC")
}
