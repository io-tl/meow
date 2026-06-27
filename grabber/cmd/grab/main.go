package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"

	debug "meow/grabber/internal/debug"
	enrichmentcmd "meow/grabber/internal/enrichment/cmd"
	fingerprintcmd "meow/grabber/internal/fingerprint/cmd"
	localcmd "meow/grabber/internal/local/cmd"
	"meow/grabber/pkg/common"
	"meow/grabber/pkg/enrichment/modules"

	// Import all enrichment modules so init() registers them
	_ "meow/grabber/pkg/enrichment/modules"
)

const version = "0.1"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]

	switch cmd {
	case "finger", "fingerprint":
		runFinger(os.Args[2:])
	case "enrich", "enrichment":
		runEnrich(os.Args[2:])
	case "local":
		runLocal(os.Args[2:])
	case "debug":
		debug.DebugMain(os.Args[1:])
	case "modules":
		listModules()
	case "-h", "--help", "help":
		printUsage()
	case "-v", "--version", "version":
		fmt.Printf("grab v%s\n", version)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

// runFinger parses finger-specific flags and launches the fingerprint service.
func runFinger(args []string) {
	configPath := ""
	workers := 0
	natsURL := ""
	natsToken := ""
	probeTimeout := 0
	globalTimeout := 0
	debug := false

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-c", "--config":
			if i+1 < len(args) {
				i++
				configPath = args[i]
			} else {
				fatal("-c requires a path argument")
			}
		case "-w", "--workers":
			if i+1 < len(args) {
				i++
				fmt.Sscanf(args[i], "%d", &workers)
			} else {
				fatal("-w requires a number argument")
			}
		case "--nats-url":
			if i+1 < len(args) {
				i++
				natsURL = args[i]
			} else {
				fatal("--nats-url requires an argument")
			}
		case "--nats-token":
			if i+1 < len(args) {
				i++
				natsToken = args[i]
			} else {
				fatal("--nats-token requires an argument")
			}
		case "--probe-timeout":
			if i+1 < len(args) {
				i++
				fmt.Sscanf(args[i], "%d", &probeTimeout)
			} else {
				fatal("--probe-timeout requires a number (ms)")
			}
		case "--global-timeout":
			if i+1 < len(args) {
				i++
				fmt.Sscanf(args[i], "%d", &globalTimeout)
			} else {
				fatal("--global-timeout requires a number (ms)")
			}
		case "-d", "--debug":
			debug = true
		case "-h", "--help":
			printFingerHelp()
			return
		default:
			if strings.HasPrefix(args[i], "-") {
				fatalf("unknown flag: %s (see 'grab finger --help')", args[i])
			}
		}
	}

	cfg := loadOrDefaultConfig(configPath, natsURL, natsToken)
	if workers > 0 {
		cfg.Fingerprint.Workers = workers
	}
	if probeTimeout > 0 {
		cfg.Fingerprint.ProbeTimeoutMS = probeTimeout
	}
	if globalTimeout > 0 {
		cfg.Fingerprint.GlobalTimeoutMS = globalTimeout
	}
	if debug {
		cfg.Logging.Level = "debug"
	}
	fingerprintcmd.Main(cfg)
}

// runEnrich parses enrich-specific flags and launches the enrichment service.
func runEnrich(args []string) {
	configPath := ""
	workers := 0
	natsURL := ""
	natsToken := ""
	enrichTimeout := 0
	globalTimeout := 0
	debug := false

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-c", "--config":
			if i+1 < len(args) {
				i++
				configPath = args[i]
			} else {
				fatal("-c requires a path argument")
			}
		case "-w", "--workers":
			if i+1 < len(args) {
				i++
				fmt.Sscanf(args[i], "%d", &workers)
			} else {
				fatal("-w requires a number argument")
			}
		case "--nats-url":
			if i+1 < len(args) {
				i++
				natsURL = args[i]
			} else {
				fatal("--nats-url requires an argument")
			}
		case "--nats-token":
			if i+1 < len(args) {
				i++
				natsToken = args[i]
			} else {
				fatal("--nats-token requires an argument")
			}
		case "--enrich-timeout":
			if i+1 < len(args) {
				i++
				fmt.Sscanf(args[i], "%d", &enrichTimeout)
			} else {
				fatal("--enrich-timeout requires a number (ms)")
			}
		case "--global-timeout":
			if i+1 < len(args) {
				i++
				fmt.Sscanf(args[i], "%d", &globalTimeout)
			} else {
				fatal("--global-timeout requires a number (ms)")
			}
		case "-d", "--debug":
			debug = true
		case "-h", "--help":
			printEnrichHelp()
			return
		default:
			if strings.HasPrefix(args[i], "-") {
				fatalf("unknown flag: %s (see 'grab enrich --help')", args[i])
			}
		}
	}

	cfg := loadOrDefaultConfig(configPath, natsURL, natsToken)
	if workers > 0 {
		cfg.Enrichment.Workers = workers
	}
	if enrichTimeout > 0 {
		cfg.Enrichment.EnrichTimeoutMS = enrichTimeout
	}
	if globalTimeout > 0 {
		cfg.Enrichment.GlobalTimeoutMS = globalTimeout
	}
	if debug {
		cfg.Logging.Level = "debug"
	}
	enrichmentcmd.Main(cfg)
}

// runLocal parses local-specific flags and launches fingerprint + enrichment in one process.
func runLocal(args []string) {
	configPath := ""
	workers := 0
	natsURL := ""
	natsToken := ""
	probeTimeout := 0
	enrichTimeout := 0
	globalTimeout := 0
	debug := false

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-c", "--config":
			if i+1 < len(args) {
				i++
				configPath = args[i]
			} else {
				fatal("-c requires a path argument")
			}
		case "-w", "--workers":
			if i+1 < len(args) {
				i++
				fmt.Sscanf(args[i], "%d", &workers)
			} else {
				fatal("-w requires a number argument")
			}
		case "--nats-url":
			if i+1 < len(args) {
				i++
				natsURL = args[i]
			} else {
				fatal("--nats-url requires an argument")
			}
		case "--nats-token":
			if i+1 < len(args) {
				i++
				natsToken = args[i]
			} else {
				fatal("--nats-token requires an argument")
			}
		case "--probe-timeout":
			if i+1 < len(args) {
				i++
				fmt.Sscanf(args[i], "%d", &probeTimeout)
			} else {
				fatal("--probe-timeout requires a number (ms)")
			}
		case "--enrich-timeout":
			if i+1 < len(args) {
				i++
				fmt.Sscanf(args[i], "%d", &enrichTimeout)
			} else {
				fatal("--enrich-timeout requires a number (ms)")
			}
		case "--global-timeout":
			if i+1 < len(args) {
				i++
				fmt.Sscanf(args[i], "%d", &globalTimeout)
			} else {
				fatal("--global-timeout requires a number (ms)")
			}
		case "-d", "--debug":
			debug = true
		case "-h", "--help":
			printLocalHelp()
			return
		default:
			if strings.HasPrefix(args[i], "-") {
				fatalf("unknown flag: %s (see 'grab local --help')", args[i])
			}
		}
	}

	cfg := loadOrDefaultConfig(configPath, natsURL, natsToken)
	if workers > 0 {
		cfg.Fingerprint.Workers = workers
	}
	if probeTimeout > 0 {
		cfg.Fingerprint.ProbeTimeoutMS = probeTimeout
	}
	if globalTimeout > 0 {
		cfg.Fingerprint.GlobalTimeoutMS = globalTimeout
		cfg.Enrichment.GlobalTimeoutMS = globalTimeout
	}
	if enrichTimeout > 0 {
		cfg.Enrichment.EnrichTimeoutMS = enrichTimeout
	}
	if debug {
		cfg.Logging.Level = "debug"
	}
	localcmd.Main(cfg)
}

// listModules prints all registered enrichment modules in a readable table.
func listModules() {
	allModules := modules.GetAll()

	// Sort by name for stable output
	sort.Slice(allModules, func(i, j int) bool {
		return allModules[i].Name() < allModules[j].Name()
	})

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "MODULE\tALIASES\tENRICH\tTIMEOUT\n")
	fmt.Fprintf(w, "------\t-------\t------\t-------\n")

	for _, m := range allModules {
		aliases := "-"
		if len(m.Aliases()) > 0 {
			aliases = strings.Join(m.Aliases(), ", ")
		}

		enrich := "yes"
		if !m.ShouldEnrich() {
			enrich = "no"
		}

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
			m.Name(), aliases, enrich, m.DefaultTimeout())
	}
	w.Flush()

	fmt.Printf("\nTotal: %d modules\n", len(allModules))
}

func printUsage() {
	fmt.Printf(`meow grab v%s

Usage:
  grab <command> [flags]

Commands:
  finger    Run fingerprint service
  enrich    Run enrichment service
  local     Run fingerprint + enrichment in one process
  debug     Debug modules (without NATS)
  modules   List all enrichment modules

Flags:
  -h, --help       Show help
  -v, --version    Show version

Run 'grab <command> --help' for command-specific options.

Examples:
  grab finger -c config.yaml
  grab finger --nats-url nats://localhost:4222 --nats-token SECRET
  grab enrich -c config.yaml -w 20
  grab enrich --nats-url nats://localhost:4222
  grab local -c config.yaml
  grab modules
  grab debug finger -host 192.168.0.254 -port 22
  grab debug enrich -host 162.159.129.73 -port 443 -service https -domain example.com

Environment variables (MEOW_* namespace, shared across all meow modules):
  MEOW_NATS_URL    Alternative to --nats-url
  MEOW_NATS_TOKEN  Alternative to --nats-token
  MEOW_DEBUG       Alternative to --debug
`, version)
}

func printFingerHelp() {
	fmt.Print(`Usage: grab finger [flags]

Run the fingerprint service. Subscribes to scan.port.open on NATS,
fingerprints each port, and publishes to scan.port.fingerprinted.

Config file is optional if --nats-url is provided (defaults will be used).

Flags:
  -c, --config string       Config file (default: config.yaml)
  -w, --workers int         Override worker count
      --nats-url string     NATS server URL (or env: MEOW_NATS_URL)
      --nats-token string   NATS auth token (or env: MEOW_NATS_TOKEN)
      --probe-timeout int   Per-probe timeout in ms (default: 9000)
      --global-timeout int  Global timeout per port in ms (default: 30000)
  -d, --debug               Enable debug logging (or env: MEOW_DEBUG)
  -h, --help                Show help

Examples:
  grab finger -c config.yaml
  grab finger --nats-url nats://localhost:4222 --nats-token SECRET
  grab finger --nats-url nats://localhost:4222 --probe-timeout 5000

Environment variables (MEOW_* namespace, shared across all meow modules):
  MEOW_NATS_URL    Alternative to --nats-url
  MEOW_NATS_TOKEN  Alternative to --nats-token
  MEOW_DEBUG       Alternative to --debug
`)
}

func printEnrichHelp() {
	fmt.Print(`Usage: grab enrich [flags]

Run the enrichment service. Subscribes to scan.port.fingerprinted on NATS,
enriches each service with protocol-specific data, and publishes to
scan.port.enriched.

Config file is optional if --nats-url is provided (defaults will be used).

Flags:
  -c, --config string       Config file (default: config.yaml)
  -w, --workers int         Override worker count
      --nats-url string     NATS server URL (or env: MEOW_NATS_URL)
      --nats-token string   NATS auth token (or env: MEOW_NATS_TOKEN)
      --enrich-timeout int  Per-module scan timeout in ms (default: 10000)
      --global-timeout int  Hard deadline per job in ms (default: 30000)
  -d, --debug               Enable debug logging (or env: MEOW_DEBUG)
  -h, --help                Show help

See 'grab modules' to list available enrichment modules.

Examples:
  grab enrich -c config.yaml
  grab enrich --nats-url nats://localhost:4222 --nats-token SECRET
  grab enrich --nats-url nats://localhost:4222 --enrich-timeout 15000

Environment variables (MEOW_* namespace, shared across all meow modules):
  MEOW_NATS_URL    Alternative to --nats-url
  MEOW_NATS_TOKEN  Alternative to --nats-token
  MEOW_DEBUG       Alternative to --debug
`)
}

func printLocalHelp() {
	fmt.Print(`Usage: grab local [flags]

Run fingerprint and enrichment services in a single process.
Equivalent to running 'grab finger' and 'grab enrich' together.

Config file is optional if --nats-url is provided (defaults will be used).

Flags:
  -c, --config string       Config file (default: config.yaml)
  -w, --workers int         Override worker count
      --nats-url string     NATS server URL (or env: MEOW_NATS_URL)
      --nats-token string   NATS auth token (or env: MEOW_NATS_TOKEN)
      --probe-timeout int   Per-probe timeout in ms (default: 9000)
      --enrich-timeout int  Per-module scan timeout in ms (default: 10000)
      --global-timeout int  Global timeout in ms (default: 30000)
  -d, --debug               Enable debug logging (or env: MEOW_DEBUG)
  -h, --help                Show help

Examples:
  grab local -c config.yaml
  grab local --nats-url nats://localhost:4222 --nats-token SECRET
  grab local --nats-url nats://localhost:4222 --probe-timeout 5000 --enrich-timeout 15000

Environment variables (MEOW_* namespace, shared across all meow modules):
  MEOW_NATS_URL    Alternative to --nats-url
  MEOW_NATS_TOKEN  Alternative to --nats-token
  MEOW_DEBUG       Alternative to --debug
`)
}

// loadOrDefaultConfig loads config from file if provided/exists, or uses defaults with CLI overrides.
// If no config file and no natsURL, it tries config.yaml as fallback.
func loadOrDefaultConfig(configPath, natsURL, natsToken string) *common.Config {
	var cfg *common.Config

	if configPath != "" {
		// Explicit config file requested
		abs, err := filepath.Abs(configPath)
		if err != nil {
			abs = configPath
		}
		loaded, err := common.LoadConfig(abs)
		if err != nil {
			fatalf("failed to load config %s: %v", abs, err)
		}
		fmt.Fprintf(os.Stderr, "Using config: %s\n", abs)
		cfg = loaded
	} else if natsURL != "" {
		// No config file but nats-url provided: use defaults
		cfg = common.DefaultConfig()
		fmt.Fprintf(os.Stderr, "No config file, using defaults with --nats-url\n")
	} else {
		// Try default config.yaml, fall back to defaults
		abs, err := filepath.Abs("config.yaml")
		if err != nil {
			abs = "config.yaml"
		}
		if _, err := os.Stat(abs); os.IsNotExist(err) {
			cfg = common.DefaultConfig()
			fmt.Fprintf(os.Stderr, "No config file found, trying %s\n", cfg.NATS.URL)
		} else {
			loaded, err := common.LoadConfig(abs)
			if err != nil {
				fatalf("failed to load config %s: %v", abs, err)
			}
			fmt.Fprintf(os.Stderr, "Using config: %s\n", abs)
			cfg = loaded
		}
	}

	// MEOW_* env overrides (after config file, before CLI flags)
	if v := os.Getenv("MEOW_NATS_URL"); v != "" {
		cfg.NATS.URL = v
	}
	if v := os.Getenv("MEOW_NATS_TOKEN"); v != "" {
		cfg.NATS.Auth.Token = v
	}
	if os.Getenv("MEOW_DEBUG") != "" {
		cfg.Logging.Level = "debug"
	}

	// CLI flags override env and config file values
	if natsURL != "" {
		cfg.NATS.URL = natsURL
	}
	if natsToken != "" {
		cfg.NATS.Auth.Token = natsToken
	}

	return cfg
}

func fatal(msg string) {
	fmt.Fprintf(os.Stderr, "Error: %s\n", msg)
	os.Exit(1)
}

func fatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "Error: "+format+"\n", args...)
	os.Exit(1)
}
