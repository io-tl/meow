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

// MetricsSnapshot représente un snapshot de métriques à un instant T
type MetricsSnapshot struct {
	Timestamp   time.Time
	Scans       uint64
	Timeouts    uint64
	Errors      uint64
	TimeoutRate float64
	Workers     int
	Adjustment  string // "increase", "decrease", "stable"
}

// WorkerTuner ajuste automatiquement le nombre de workers selon les performances
type WorkerTuner struct {
	// Métriques
	totalScans    uint64
	totalTimeouts uint64
	totalErrors   uint64
	lastCheck     time.Time

	// Config
	minWorkers    int
	maxWorkers    int
	targetTimeout float64 // Taux de timeout cible (ex: 5%)

	// State
	currentWorkers          int
	adjustments             int
	lastAdjustmentDir       int // -1 = decrease, 0 = none, +1 = increase
	consecutiveOscillations int // Compteur d'oscillations

	// Historique (buffer circulaire des 10 dernières périodes)
	history     []MetricsSnapshot
	historyIdx  int
	historySize int

	// Thread-safety
	mu sync.RWMutex
}

// NewWorkerTuner crée un tuner automatique
func NewWorkerTuner(initialWorkers int) *WorkerTuner {
	numCPU := runtime.NumCPU()

	// Minimum plus élevé pour VPS moderne (au moins 20 workers même si peu de CPUs)
	minWorkers := numCPU * 2
	if minWorkers < 20 {
		minWorkers = 20
	}

	return &WorkerTuner{
		minWorkers:              minWorkers,     // Minimum: 20 ou 2*CPU (agressif pour I/O bound)
		maxWorkers:              300,            // Maximum: 300 workers (default from config)
		targetTimeout:           0.05,           // 5% de timeout acceptable
		currentWorkers:          initialWorkers, // Démarrer avec le nombre recommandé
		lastCheck:               time.Now(),
		lastAdjustmentDir:       0,
		consecutiveOscillations: 0,
		history:                 make([]MetricsSnapshot, 10),
		historyIdx:              0,
		historySize:             0,
	}
}

// RecordScan enregistre le résultat d'un scan
func (wt *WorkerTuner) RecordScan(timedout bool, errored bool) {
	scans := atomic.AddUint64(&wt.totalScans, 1)
	if timedout {
		timeouts := atomic.AddUint64(&wt.totalTimeouts, 1)
		if scans%10 == 0 { // Log tous les 10 scans
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

// addSnapshot ajoute un snapshot à l'historique (buffer circulaire)
func (wt *WorkerTuner) addSnapshot(snapshot MetricsSnapshot) {
	wt.mu.Lock()
	defer wt.mu.Unlock()

	wt.history[wt.historyIdx] = snapshot
	wt.historyIdx = (wt.historyIdx + 1) % 10
	if wt.historySize < 10 {
		wt.historySize++
	}
}

// GetHistory retourne l'historique des métriques
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

// detectOscillation détecte si on oscille (augmente puis diminue répétitivement)
func (wt *WorkerTuner) detectOscillation(newDir int) bool {
	wt.mu.Lock()
	defer wt.mu.Unlock()

	// Si changement de direction, c'est une oscillation potentielle
	if wt.lastAdjustmentDir != 0 && newDir != 0 && wt.lastAdjustmentDir != newDir {
		wt.consecutiveOscillations++
		wt.lastAdjustmentDir = newDir
		return wt.consecutiveOscillations >= 3 // 3 oscillations = problème
	}

	wt.lastAdjustmentDir = newDir
	if newDir == 0 {
		wt.consecutiveOscillations = 0 // Reset si stable
	}
	return false
}

// ShouldAdjust vérifie si on doit ajuster les workers (AMÉLIORATION: ajustement graduel)
func (wt *WorkerTuner) ShouldAdjust() (newWorkers int, shouldChange bool) {
	// Vérifier toutes les 10 secondes minimum (réactivité accrue)
	wt.mu.RLock()
	timeSince := time.Since(wt.lastCheck)
	wt.mu.RUnlock()

	if timeSince < 10*time.Second {
		return wt.currentWorkers, false
	}

	scans := atomic.LoadUint64(&wt.totalScans)
	timeouts := atomic.LoadUint64(&wt.totalTimeouts)
	errors := atomic.LoadUint64(&wt.totalErrors)

	// Réduire le seuil à 10 scans pour réagir plus vite
	if scans < 10 {
		return wt.currentWorkers, false
	}

	timeoutRate := float64(timeouts) / float64(scans)

	// Créer un snapshot avant de reset les compteurs
	snapshot := MetricsSnapshot{
		Timestamp:   time.Now(),
		Scans:       scans,
		Timeouts:    timeouts,
		Errors:      errors,
		TimeoutRate: timeoutRate,
		Workers:     wt.currentWorkers,
		Adjustment:  "stable",
	}

	// Reset les compteurs
	atomic.StoreUint64(&wt.totalScans, 0)
	atomic.StoreUint64(&wt.totalTimeouts, 0)
	atomic.StoreUint64(&wt.totalErrors, 0)
	wt.mu.Lock()
	wt.lastCheck = time.Now()
	wt.mu.Unlock()

	adjustmentDir := 0

	// AMÉLIORATION 1: Réduction GRADUELLE au lieu d'agressive
	if timeoutRate > wt.targetTimeout*2 { // > 10%
		adjustmentDir = -1

		// Détecter oscillation
		if wt.detectOscillation(adjustmentDir) {
			log.Info().Int("workers", wt.currentWorkers).Msg("TUNE: Oscillation detected - Stabilizing")
			snapshot.Adjustment = "oscillation-stabilize"
			wt.addSnapshot(snapshot)
			return wt.currentWorkers, false
		}

		// Réduction graduelle: -20% par cycle, plafonné à -50 workers max
		reduction := int(float64(wt.currentWorkers) * 0.20)
		if reduction > 50 {
			reduction = 50
		}
		if reduction < 10 {
			reduction = 10 // Au moins -10 workers
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
		// AMÉLIORATION 2: Augmentation adaptative selon qualité
		adjustmentDir = 1

		// Détecter oscillation
		if wt.detectOscillation(adjustmentDir) {
			log.Info().Int("workers", wt.currentWorkers).Msg("TUNE: Oscillation detected - Stabilizing")
			snapshot.Adjustment = "oscillation-stabilize"
			wt.addSnapshot(snapshot)
			return wt.currentWorkers, false
		}

		increase := 10 // Par défaut: +10 workers

		// Si conditions excellentes (< 2.5% timeout), accélérer
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

	// Pas de changement mais ajouter le snapshot
	snapshot.Adjustment = "stable"
	wt.addSnapshot(snapshot)
	return wt.currentWorkers, false
}

// GetRecommendedWorkers calcule le nombre optimal de workers selon les ressources
// AMÉLIORATION: Warm-up progressif au lieu de démarrage agressif
func GetRecommendedWorkers() int {
	numCPU := runtime.NumCPU()

	// Lire les stats mémoire
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	allocMB := m.Alloc / (1024 * 1024)
	sysMB := m.Sys / (1024 * 1024)

	// AMÉLIORATION: WARM-UP PROGRESSIF
	// Démarrer avec un nombre raisonnable et laisser l'autotune augmenter progressivement
	// Avantages:
	// - Évite le spike de charge initial (rate-limiting, blacklist)
	// - Détecte rapidement les limites réseau/système
	// - Réduit le risque de crasher la cible
	//
	// Stratégie: min(numCPU * 10, 50) pour démarrer doucement
	// L'autotune augmentera de +10/+20/+30 par cycle (10s) jusqu'au max

	recommended := numCPU * 10 // Ex: 8 cores = 80 workers au démarrage
	if recommended > 50 {
		recommended = 50 // Plafonner à 50 pour warm-up
	}
	if recommended < 20 {
		recommended = 20 // Minimum 20 workers
	}

	// Seulement si système très puissant (16+ cores), démarrer plus haut
	if numCPU >= 16 {
		recommended = 100 // Systèmes puissants peuvent démarrer à 100
	}

	warmupTime := (300 - recommended) / 20 * 10 // Temps estimé pour atteindre max (300 workers)
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

// AdaptiveConfig ajuste les timeouts selon le type de service
type AdaptiveConfig struct {
	// Timeouts adaptatifs par protocole
	FastServices   []string // HTTP, SSH: 5s
	MediumServices []string // SMTP, MySQL: 10s
	SlowServices   []string // Custom apps: 30s

	DefaultTimeout time.Duration
	FastTimeout    time.Duration
	MediumTimeout  time.Duration
	SlowTimeout    time.Duration
}

// DefaultAdaptiveConfig retourne la config adaptative par défaut
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

// GetTimeoutForService retourne le timeout adapté au service détecté
func (ac *AdaptiveConfig) GetTimeoutForService(service string) time.Duration {
	// Vérifier si c'est un service rapide
	if slices.Contains(ac.FastServices, service) {
		return ac.FastTimeout
	}

	// Vérifier si c'est un service moyen
	if slices.Contains(ac.MediumServices, service) {
		return ac.MediumTimeout
	}

	// Vérifier si c'est un service lent
	if slices.Contains(ac.SlowServices, service) {
		return ac.SlowTimeout
	}

	return ac.DefaultTimeout
}

// VPSResourceMonitor surveille les ressources du VPS
type VPSResourceMonitor struct {
	highMemCount int
	totalRAM     uint64 // RAM totale système (détectée au démarrage)
}

// getTotalSystemRAM is defined in sysinfo_linux.go / sysinfo_other.go

// NewVPSResourceMonitor crée un moniteur de ressources
func NewVPSResourceMonitor() *VPSResourceMonitor {
	totalRAM := getTotalSystemRAM()
	log.Info().Uint64("ram_mb", totalRAM).Msg("TUNE: Detected system RAM")

	return &VPSResourceMonitor{
		totalRAM: totalRAM,
	}
}

// CheckResources vérifie l'utilisation des ressources (AMÉLIORATION: seuils adaptatifs)
func (vrm *VPSResourceMonitor) CheckResources() (cpuOK, memOK bool, warnings []string) {
	warnings = make([]string, 0)

	// Vérifier la mémoire
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	allocMB := m.Alloc / (1024 * 1024)
	sysMB := m.Sys / (1024 * 1024)
	gcPct := float64(m.GCCPUFraction) * 100

	// AMÉLIORATION: Seuil adaptatif basé sur la RAM totale du système
	memUsagePct := float64(m.Alloc) / float64(m.Sys) * 100

	// Calculer le seuil: 85% de la RAM totale (au lieu de 4GB fixe)
	memThresholdMB := uint64(float64(vrm.totalRAM) * 0.85)

	// Warning si:
	// 1. Plus de 95% de la mémoire allouée est utilisée (pression interne Go)
	// 2. OU si on dépasse 85% de la RAM totale système
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

	// Alerte si GC utilise > 10% du CPU
	if gcPct > 10 {
		warnings = append(warnings,
			fmt.Sprintf("High GC CPU usage: %.1f%%", gcPct))
	}

	// Alerte si beaucoup de goroutines
	numGoroutines := runtime.NumGoroutine()
	if numGoroutines > 10000 {
		warnings = append(warnings,
			fmt.Sprintf("High goroutine count: %d", numGoroutines))
	}

	// CPU check (approximatif via nombre de goroutines runnable)
	cpuOK = numGoroutines < 5000

	return cpuOK, memOK, warnings
}

// ShouldThrottle détermine si on doit throttler les scans
func (vrm *VPSResourceMonitor) ShouldThrottle() bool {
	cpuOK, memOK, warnings := vrm.CheckResources()

	if len(warnings) > 0 {
		for _, warning := range warnings {
			log.Warn().Str("warning", warning).Msg("TUNE: Resource warning")
		}
	}

	// Throttler si CPU ou mémoire sont surchargés pendant 3 checks consécutifs
	if !cpuOK || !memOK {
		if vrm.highMemCount > 3 {
			return true
		}
	}

	return false
}

// PrintResourceStats affiche les stats des ressources
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
