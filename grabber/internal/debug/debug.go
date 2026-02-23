package debug

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/rs/zerolog/log"
	"meow/grabber/internal/fingerprint/grab"
	"meow/grabber/pkg/enrichment/modules"
)

// DebugConfig contient la configuration pour les tests en mode debug
type DebugConfig struct {
	Host      string
	Port      int
	Service   string
	Domain    string
	Timeout   time.Duration
	Intensity int
	Debug     bool
}

// DebugFingerprint teste le fingerprinting sans passer par NATS
func DebugFingerprint(cfg *DebugConfig) {
	log.Info().
		Str("host", cfg.Host).
		Int("port", cfg.Port).
		Str("service", cfg.Service).
		Bool("debug", cfg.Debug).
		Msg("=== DEBUG FINGERPRINT ===")

	// Lancer le fingerprinting
	result, err := grab.GrabWithOptions(
		cfg.Host,
		cfg.Port,
		cfg.Timeout,
		cfg.Intensity,
		30*time.Second,
		cfg.Debug,
	)

	if err != nil {
		log.Error().
			Err(err).
			Msg("Fingerprint failed")
		return
	}

	if result == nil {
		log.Info().Msg("No service detected")
		return
	}

	// Afficher les résultats
	fmt.Printf("\n=== FINGERPRINT RESULT ===\n")
	fmt.Printf("Host: %s\n", cfg.Host)
	fmt.Printf("Port: %d\n", cfg.Port)

	// Afficher le service avec ? si uncertain (comme nmap)
	serviceDisplay := result.Service
	if result.Uncertain {
		serviceDisplay += "?"
	}
	fmt.Printf("Service: %s\n", serviceDisplay)

	fmt.Printf("Product: %s\n", result.Product)
	fmt.Printf("Version: %s\n", result.Version)
	fmt.Printf("Info: %s\n", result.Info)
	fmt.Printf("Hostname: %s\n", result.Hostname)
	fmt.Printf("OS: %s\n", result.OS)
	fmt.Printf("Device Type: %s\n", result.DeviceType)
	fmt.Printf("Probe Used: %s\n", result.Probe)
	fmt.Printf("Is Soft Match: %v\n", result.IsSoft())

	if result.Uncertain {
		fmt.Printf("⚠ Uncertain: Service guessed from port number (no probe matched)\n")
	}

	if len(result.CPE) > 0 {
		fmt.Printf("CPE: %v\n", result.CPE)
	}

	if result.TLSVersion > 0 {
		fmt.Printf("TLS Version: 0x%04x\n", result.TLSVersion)
		fmt.Printf("Cipher Suite: 0x%04x\n", result.CipherSuite)
		fmt.Printf("Server Name: %s\n", result.ServerName)
		fmt.Printf("Certificates: %d\n", len(result.CertificatesPEM))
	}

	if result.JARMFingerprint != "" {
		fmt.Printf("JARM Fingerprint: %s\n", result.JARMFingerprint)
	}

	// Toujours afficher la bannière si présente (c'est une commande debug après tout)
	if result.RawResponse != "" {
		fmt.Printf("\n=== RAW RESPONSE (Banner) ===\n")
		// Limiter l'affichage pour éviter trop de sortie
		raw := result.RawResponse
		if len(raw) > 1000 {
			raw = raw[:1000] + "..."
		}
		fmt.Printf("%s\n", raw)
	}
}

// DebugEnrichment teste l'enrichment sans passer par NATS
func DebugEnrichment(cfg *DebugConfig) {
	log.Info().
		Str("host", cfg.Host).
		Int("port", cfg.Port).
		Str("service", cfg.Service).
		Str("domain", cfg.Domain).
		Msg("=== DEBUG ENRICHMENT ===")

	// Vérifier si le service est supporté
	module, ok := modules.Get(cfg.Service)
	if !ok {
		log.Error().
			Str("service", cfg.Service).
			Msg("Service not supported for enrichment")

		// Lister les services disponibles
		fmt.Printf("\nAvailable services:\n")
		services := modules.ListServices()
		for name := range services {
			fmt.Printf("  - %s\n", name)
		}
		return
	}

	if !module.ShouldEnrich() {
		log.Warn().
			Str("service", cfg.Service).
			Msg("Service is configured to skip enrichment")
		return
	}

	// Lancer l'enrichment
	var data interface{}
	var err error

	startTime := time.Now()

	if cfg.Domain != "" {
		log.Info().Str("domain", cfg.Domain).Msg("Using SNI")
		data, err = module.ScanWithSNI(cfg.Host, cfg.Port, cfg.Domain)
		if data == nil && err == nil {
			log.Info().Msg("SNI scan returned nil, trying regular scan")
			data, err = module.Scan(cfg.Host, cfg.Port)
		}
	} else {
		data, err = module.Scan(cfg.Host, cfg.Port)
	}

	duration := time.Since(startTime)

	if err != nil {
		log.Error().
			Err(err).
			Dur("duration", duration).
			Msg("Enrichment failed")
		return
	}

	if data == nil {
		log.Info().
			Dur("duration", duration).
			Msg("Enrichment returned no data")
		return
	}

	// Afficher les résultats
	fmt.Printf("\n=== ENRICHMENT RESULT ===\n")
	fmt.Printf("Host: %s\n", cfg.Host)
	fmt.Printf("Port: %d\n", cfg.Port)
	fmt.Printf("Service: %s\n", cfg.Service)
	if cfg.Domain != "" {
		fmt.Printf("Domain: %s\n", cfg.Domain)
	}
	fmt.Printf("Duration: %v\n", duration)

	// Afficher les données en JSON
	fmt.Printf("\nData:\n")
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		fmt.Printf("%+v\n", data)
	} else {
		fmt.Printf("%s\n", string(jsonData))
	}
}

// DebugFlags parse les arguments en ligne de commande pour le mode debug
func ParseDebugFlags() *DebugConfig {
	cfg := &DebugConfig{
		Timeout:   5 * time.Second,
		Intensity: 5,
		Debug:     false,
	}

	flag.StringVar(&cfg.Host, "host", "127.0.0.1", "Target host/IP")
	flag.IntVar(&cfg.Port, "port", 80, "Target port")
	flag.StringVar(&cfg.Service, "service", "", "Service for enrichment (required for enrichment)")
	flag.StringVar(&cfg.Domain, "domain", "", "Domain for SNI (HTTPS)")
	flag.DurationVar(&cfg.Timeout, "timeout", 5*time.Second, "Probe timeout")
	flag.IntVar(&cfg.Intensity, "intensity", 5, "Scan intensity (1-9)")
	flag.BoolVar(&cfg.Debug, "debug", false, "Enable debug output")

	flag.Parse()

	return cfg
}

// DebugMain est le point d'entrée pour les commandes de debug
func DebugMain(args []string) {
	if len(args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s debug <finger|enrich|test> [options]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nCommands:\n")
		fmt.Fprintf(os.Stderr, "  finger  - Test fingerprinting\n")
		fmt.Fprintf(os.Stderr, "  enrich  - Test enrichment\n")
		fmt.Fprintf(os.Stderr, "  test    - Run unit tests and benchmarks\n")
		fmt.Fprintf(os.Stderr, "\nOptions:\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	command := args[1]

	switch command {
	case "finger":
		// Parser les flags après la commande
		os.Args = append([]string{os.Args[0]}, args[2:]...)
		cfg := ParseDebugFlags()
		DebugFingerprint(cfg)
	case "enrich":
		// Parser les flags après la commande
		os.Args = append([]string{os.Args[0]}, args[2:]...)
		cfg := ParseDebugFlags()
		if cfg.Service == "" {
			fmt.Fprintf(os.Stderr, "Error: -service is required for enrichment\n")
			os.Exit(1)
		}
		DebugEnrichment(cfg)
	case "test":
		RunTestsFromCLI(args[2:])
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
		os.Exit(1)
	}
}
