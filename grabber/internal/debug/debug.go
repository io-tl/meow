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

// DebugConfig contains the configuration for debug-mode tests
type DebugConfig struct {
	Host      string
	Port      int
	Service   string
	Domain    string
	Timeout   time.Duration
	Intensity int
	Debug     bool
}

// DebugFingerprint tests fingerprinting without going through NATS
func DebugFingerprint(cfg *DebugConfig) {
	log.Info().
		Str("host", cfg.Host).
		Int("port", cfg.Port).
		Str("service", cfg.Service).
		Bool("debug", cfg.Debug).
		Msg("=== DEBUG FINGERPRINT ===")

	// Run fingerprinting
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

	// Display the results
	fmt.Printf("\n=== FINGERPRINT RESULT ===\n")
	fmt.Printf("Host: %s\n", cfg.Host)
	fmt.Printf("Port: %d\n", cfg.Port)

	// Display the service with ? if uncertain (like nmap)
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

	// Always display the banner if present (it's a debug command after all)
	if result.RawResponse != "" {
		fmt.Printf("\n=== RAW RESPONSE (Banner) ===\n")
		// Limit the display to avoid too much output
		raw := result.RawResponse
		if len(raw) > 1000 {
			raw = raw[:1000] + "..."
		}
		fmt.Printf("%s\n", raw)
	}
}

// DebugEnrichment tests enrichment without going through NATS
func DebugEnrichment(cfg *DebugConfig) {
	log.Info().
		Str("host", cfg.Host).
		Int("port", cfg.Port).
		Str("service", cfg.Service).
		Str("domain", cfg.Domain).
		Msg("=== DEBUG ENRICHMENT ===")

	// Check whether the service is supported
	module, ok := modules.Get(cfg.Service)
	if !ok {
		log.Error().
			Str("service", cfg.Service).
			Msg("Service not supported for enrichment")

		// List the available services
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

	// Run enrichment
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

	// Display the results
	fmt.Printf("\n=== ENRICHMENT RESULT ===\n")
	fmt.Printf("Host: %s\n", cfg.Host)
	fmt.Printf("Port: %d\n", cfg.Port)
	fmt.Printf("Service: %s\n", cfg.Service)
	if cfg.Domain != "" {
		fmt.Printf("Domain: %s\n", cfg.Domain)
	}
	fmt.Printf("Duration: %v\n", duration)

	// Display the data as JSON
	fmt.Printf("\nData:\n")
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		fmt.Printf("%+v\n", data)
	} else {
		fmt.Printf("%s\n", string(jsonData))
	}
}

// ParseDebugFlags parses command-line arguments for debug mode
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

// DebugMain is the entry point for debug commands
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
		// Parse the flags after the command
		os.Args = append([]string{os.Args[0]}, args[2:]...)
		cfg := ParseDebugFlags()
		DebugFingerprint(cfg)
	case "enrich":
		// Parse the flags after the command
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
