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

// WorkerPool gère un pool de workers pour le scan de services
// Architecture inspirée de zgrab2 avec optimisations pour réduire l'empreinte mémoire
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
	workerControls []chan struct{} // Un channel par worker pour l'arrêter
}

// ScanRequest représente une demande de scan
type ScanRequest struct {
	Host          string
	Port          int
	ProbeTimeout  time.Duration
	Intensity     int
	GlobalTimeout time.Duration
	Debug         bool
	ResultChan    chan<- ScanResult // Channel optionnel pour recevoir le résultat directement
}

// ScanResult représente le résultat d'un scan
type ScanResult struct {
	Host        string
	Port        int
	Result      *ServiceResult
	Error       error
	TimeoutType string // "network", "global", "probe", "" (aucun timeout)
}

// WorkerPoolConfig configure le pool de workers
type WorkerPoolConfig struct {
	NumWorkers    int           // Nombre de workers (défaut: CPU * 4)
	QueueSize     int           // Taille des queues (défaut: NumWorkers * 4)
	ProbeTimeout  time.Duration // Timeout par probe (défaut: 5s)
	Intensity     int           // Intensité des scans (défaut: 7)
	GlobalTimeout time.Duration // Timeout global par scan (défaut: 20s)
	Debug         bool
	AutoTune      bool // Activer l'auto-tuning (recommandé pour VPS)
}

// DefaultWorkerPoolConfig retourne une config par défaut
func DefaultWorkerPoolConfig() *WorkerPoolConfig {
	// Utiliser GetRecommendedWorkers() pour calculer selon les ressources
	numWorkers := GetRecommendedWorkers()

	return &WorkerPoolConfig{
		NumWorkers:    numWorkers,
		QueueSize:     numWorkers * 4,
		ProbeTimeout:  5 * time.Second,
		Intensity:     7,
		GlobalTimeout: 20 * time.Second,
		Debug:         false,
		AutoTune:      true, // Activé par défaut
	}
}

// NewWorkerPool crée un nouveau pool de workers
func NewWorkerPool(config *WorkerPoolConfig) (*WorkerPool, error) {
	if config == nil {
		config = DefaultWorkerPoolConfig()
	}

	// Charger la ProbeDB une seule fois (singleton déjà géré par getProbeDB)
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

	// Afficher les ressources initiales
	PrintResourceStats()

	// Démarrer les workers
	pool.workerWg.Add(config.NumWorkers)
	for i := 0; i < config.NumWorkers; i++ {
		stopChan := make(chan struct{})
		pool.workerControls = append(pool.workerControls, stopChan)
		go pool.worker(i, stopChan)
	}

	// Démarrer le monitoring auto-tune si activé
	if pool.autoTune {
		go pool.autoTuneLoop()
	}

	return pool, nil
}

// worker est la fonction exécutée par chaque worker
func (p *WorkerPool) worker(id int, stopChan chan struct{}) {
	defer p.workerWg.Done()

	// Chaque worker réutilise le même context pour minimiser les allocations
	for {
		select {
		case <-p.done:
			return
		case <-stopChan:
			// Ce worker spécifique doit s'arrêter
			return
		case req, ok := <-p.inputQueue:
			if !ok {
				return // Queue fermée
			}

			// AMÉLIORATION: Adapter le timeout selon le type de service (si déjà connu)
			globalTimeout := req.GlobalTimeout
			if globalTimeout == 0 {
				globalTimeout = 20 * time.Second // Fallback par défaut
			}

			// Effectuer le scan avec timeout global
			ctx, cancel := context.WithTimeout(context.Background(), globalTimeout)

			// Channel pour recevoir le résultat
			resultChan := make(chan ScanResult, 1)

			// Lancer le scan dans une goroutine pour respecter le timeout global
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

			// Attendre le résultat ou le timeout
			select {
			case res := <-resultChan:
				atomic.AddUint64(&p.totalScanned, 1)
				isTimeout := false
				isError := false

				// AMÉLIORATION: Détecter le type de timeout/erreur
				if res.Error == nil {
					atomic.AddUint64(&p.totalSuccess, 1)
					res.TimeoutType = "" // Pas de timeout
				} else {
					atomic.AddUint64(&p.totalFailures, 1)
					isError = true

					// Classifier le type d'erreur
					errMsg := res.Error.Error()
					if strings.Contains(errMsg, "timeout") || strings.Contains(errMsg, "i/o timeout") {
						res.TimeoutType = "network" // Timeout réseau (vraie saturation)
						isTimeout = true
						atomic.AddUint64(&p.totalTimeouts, 1)
					} else if strings.Contains(errMsg, "connection reset") {
						res.TimeoutType = "" // Pas un timeout, juste une connexion fermée
						// Blacklist disabled (scanmap/blacklist dependency removed)
						// bl := blacklist.GetBlacklist()
						// bl.RecordConnectionReset(req.Host, req.Port)
					} else if strings.Contains(errMsg, "connection refused") {
						res.TimeoutType = "" // Port fermé, pas un timeout
					} else {
						res.TimeoutType = "" // Autre erreur
					}
				}

				// AMÉLIORATION: Ne pénaliser l'autotune QUE pour les timeouts réseau
				if p.autoTune {
					p.tuner.RecordScan(isTimeout, isError)
				}

				// Envoyer le résultat au bon destinataire
				if req.ResultChan != nil {
					// Envoi direct sur le channel fourni
					select {
					case req.ResultChan <- res:
					case <-p.done:
						cancel()
						return
					}
				} else {
					// Envoi sur la queue globale
					select {
					case p.outputQueue <- res:
					case <-p.done:
						cancel()
						return
					}
				}
			case <-ctx.Done():
				// AMÉLIORATION: Timeout global (pas forcément un problème réseau)
				atomic.AddUint64(&p.totalScanned, 1)
				atomic.AddUint64(&p.totalFailures, 1)
				atomic.AddUint64(&p.totalTimeouts, 1)

				// Timeout global = scan trop lent, mais pas forcément saturation réseau
				// Ne pas pénaliser autotune aussi fort qu'un vrai timeout réseau
				if p.autoTune {
					p.tuner.RecordScan(false, true) // Compter comme erreur, pas timeout
				}

				timeoutResult := ScanResult{
					Host:        req.Host,
					Port:        req.Port,
					Result:      nil,
					Error:       fmt.Errorf("scan timeout after %v", req.GlobalTimeout),
					TimeoutType: "global", // Timeout global (scan trop long)
				}

				// Envoyer le résultat au bon destinataire
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

// Submit soumet une requête de scan au pool (blocking with timeout)
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

// Results retourne le channel de résultats (lecture seule)
func (p *WorkerPool) Results() <-chan ScanResult {
	return p.outputQueue
}

// Close arrête le pool de workers proprement
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

// Stats retourne les statistiques du pool
func (p *WorkerPool) Stats() (scanned, success, failures uint64) {
	return atomic.LoadUint64(&p.totalScanned),
		atomic.LoadUint64(&p.totalSuccess),
		atomic.LoadUint64(&p.totalFailures)
}

// DetailedStats retourne des statistiques détaillées
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

// adjustWorkers ajuste dynamiquement le nombre de workers
func (p *WorkerPool) adjustWorkers(targetWorkers int) {
	p.workersMu.Lock()
	defer p.workersMu.Unlock()

	current := p.activeWorkers

	if targetWorkers == current {
		return
	}

	if targetWorkers > current {
		// Ajouter des workers
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
		// Retirer des workers
		numToRemove := current - targetWorkers
		log.Info().
			Int("removing", numToRemove).
			Int("from", current).
			Int("to", targetWorkers).
			Msg("Removing workers")

		// Fermer les channels de contrôle des derniers workers
		for i := 0; i < numToRemove && len(p.workerControls) > 0; i++ {
			lastIdx := len(p.workerControls) - 1
			close(p.workerControls[lastIdx])
			p.workerControls = p.workerControls[:lastIdx]
		}

		p.activeWorkers = targetWorkers
	}
}

var poolLog string

// autoTuneLoop surveille et ajuste le nombre de workers
func (p *WorkerPool) autoTuneLoop() {
	ticker := time.NewTicker(10 * time.Second) // Check toutes les 10s pour réactivité
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// AMÉLIORATION: Implémenter réellement le throttling
			shouldThrottle := p.resourceMonitor.ShouldThrottle()
			if shouldThrottle {
				log.Warn().Msg("TUNE: Resource throttling active - Pausing submissions")
				// Réduire agressivement les workers si throttle actif
				p.workersMu.RLock()
				currentWorkers := p.activeWorkers
				p.workersMu.RUnlock()

				targetWorkers := currentWorkers / 2 // Réduire de 50%
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

				// Pause pour laisser les ressources se libérer
				time.Sleep(2 * time.Second)
				continue
			}

			// Afficher les stats avec goroutine count (enrichissement désactivé)
			stats := p.DetailedStats()
			poolTmp := fmt.Sprintf("POOL: Workers=%d Scanned=%d Success=%.1f%% Timeout=%.1f%% Queue=%d/%d",
				stats["workers"], stats["scanned"], stats["success_rate"],
				stats["timeout_rate"], stats["queue_input"], stats["queue_output"])
			if poolLog != poolTmp {
				log.Print(poolTmp)
				poolLog = poolTmp
			}
			// Ajuster dynamiquement le nombre de workers
			if newWorkers, shouldChange := p.tuner.ShouldAdjust(); shouldChange {
				p.adjustWorkers(newWorkers)
			}

		case <-p.done:
			return
		}
	}
}

// ScanBatch scanne un batch d'hôtes en parallèle et retourne tous les résultats.
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
