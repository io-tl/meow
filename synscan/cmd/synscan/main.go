package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const version = "0.1"

type cliOptions struct {
	target     string
	targetFile string
	ports      string
	topPorts   int
	iface      string
	rateLimit  int
	timeout    int
	configFile string
	natsURL    string
	natsToken  string
	debug      bool
	resume     string
	daemon     bool
}

func main() {
	opts := cliOptions{
		configFile: "config.yaml",
	}

	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-t", "--target":
			if i+1 >= len(args) {
				fatal("--target requires an argument")
			}
			i++
			opts.target = args[i]
		case "--target-file":
			if i+1 >= len(args) {
				fatal("--target-file requires an argument")
			}
			i++
			opts.targetFile = args[i]
		case "-p", "--ports":
			if i+1 >= len(args) {
				fatal("--ports requires an argument")
			}
			i++
			opts.ports = args[i]
		case "-P", "--top-ports":
			if i+1 >= len(args) {
				fatal("--top-ports requires an argument")
			}
			i++
			n, err := strconv.Atoi(args[i])
			if err != nil {
				fatalf("invalid top-ports: %s", args[i])
			}
			opts.topPorts = n
		case "-i", "--interface":
			if i+1 >= len(args) {
				fatal("--interface requires an argument")
			}
			i++
			opts.iface = args[i]
		case "-r", "--rate-limit":
			if i+1 >= len(args) {
				fatal("--rate-limit requires an argument")
			}
			i++
			n, err := strconv.Atoi(args[i])
			if err != nil {
				fatalf("invalid rate-limit: %s", args[i])
			}
			opts.rateLimit = n
		case "-T", "--timeout":
			if i+1 >= len(args) {
				fatal("--timeout requires an argument")
			}
			i++
			n, err := strconv.Atoi(args[i])
			if err != nil {
				fatalf("invalid timeout: %s", args[i])
			}
			opts.timeout = n
		case "-c", "--config":
			if i+1 >= len(args) {
				fatal("--config requires an argument")
			}
			i++
			opts.configFile = args[i]
		case "--nats-url":
			if i+1 >= len(args) {
				fatal("--nats-url requires an argument")
			}
			i++
			opts.natsURL = args[i]
		case "--nats-token":
			if i+1 >= len(args) {
				fatal("--nats-token requires an argument")
			}
			i++
			opts.natsToken = args[i]
		case "--resume":
			if i+1 >= len(args) {
				fatal("--resume requires an argument")
			}
			i++
			opts.resume = args[i]
		case "--daemon":
			opts.daemon = true
		case "-d", "--debug":
			opts.debug = true
		case "-h", "--help":
			printUsage()
			return
		case "-v", "--version":
			fmt.Printf("synscan v%s\n", version)
			return
		default:
			if strings.HasPrefix(args[i], "-") {
				fatalf("unknown flag: %s", args[i])
			}
		}
	}

	// MEOW_DEBUG env var fallback (flag takes precedence)
	if !opts.debug && os.Getenv("MEOW_DEBUG") != "" {
		opts.debug = true
	}

	config := loadConfiguration(opts)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Fprintln(os.Stderr, "\nShutting down gracefully...")
		cancel()
		time.Sleep(100 * time.Millisecond)
	}()

	if opts.daemon {
		if err := runDaemon(ctx, config, opts.debug); err != nil {
			fatal(err.Error())
		}
		return
	}

	if config.Synscan.Target.CIDR == "" && config.Synscan.Target.File == "" {
		fmt.Fprintln(os.Stderr, "Error: --target or --target-file is required")
		fmt.Fprintln(os.Stderr)
		printUsage()
		os.Exit(1)
	}

	if err := run(ctx, config, opts.debug, opts.resume); err != nil {
		fatal(err.Error())
	}
}

// loadConfiguration loads configuration with the following priority:
// 1. Default values (lowest priority)
// 2. Config file values (if file exists)
// 3. CLI flags (highest priority)
func loadConfiguration(opts cliOptions) *YAMLConfig {
	config := GetDefaultConfig()

	if opts.configFile != "" {
		if _, err := os.Stat(opts.configFile); err == nil {
			fileConfig, err := LoadConfig(opts.configFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to load config file: %v\n", err)
				fmt.Fprintln(os.Stderr, "Using default configuration")
			} else {
				config = fileConfig
			}
		}
	}

	// CLI overrides
	if opts.target != "" {
		config.Synscan.Target.CIDR = opts.target
		config.Synscan.Target.File = ""
	}
	if opts.targetFile != "" {
		config.Synscan.Target.File = opts.targetFile
		config.Synscan.Target.CIDR = ""
	}
	if opts.ports != "" {
		config.Synscan.Target.Ports = opts.ports
	}

	if opts.target != "" && opts.targetFile != "" {
		fatal("--target and --target-file are mutually exclusive")
	}
	if config.Synscan.Target.CIDR != "" && config.Synscan.Target.File != "" {
		fatal("synscan.target.cidr and synscan.target.file are mutually exclusive")
	}
	if opts.topPorts > 0 {
		config.Synscan.Target.TopPorts = opts.topPorts
	}

	// --ports and --top-ports are mutually exclusive
	if opts.ports != "" && opts.topPorts > 0 {
		fatal("--ports and --top-ports are mutually exclusive")
	}

	// Resolve top-ports: YAML top_ports also overrides YAML ports
	if config.Synscan.Target.TopPorts > 0 {
		ports, err := TopPorts(config.Synscan.Target.TopPorts)
		if err != nil {
			fatalf("invalid top-ports: %v", err)
		}
		parts := make([]string, len(ports))
		for i, p := range ports {
			parts[i] = strconv.FormatUint(uint64(p), 10)
		}
		config.Synscan.Target.Ports = strings.Join(parts, ",")
	}

	if opts.iface != "" {
		config.Synscan.Network.Interface = opts.iface
	}
	if opts.rateLimit > 0 {
		config.Synscan.Performance.RateLimit = opts.rateLimit
	}
	if opts.timeout > 0 {
		config.Synscan.Performance.TimeoutMS = opts.timeout
	}
	// MEOW_* env overrides (after YAML, before CLI flags)
	if v := os.Getenv("MEOW_NATS_URL"); v != "" {
		config.NATS.URL = v
	}
	if v := os.Getenv("MEOW_NATS_TOKEN"); v != "" {
		config.NATS.Auth.Token = v
	}

	// CLI flags override env and config file
	if opts.natsURL != "" {
		config.NATS.URL = opts.natsURL
	}
	if opts.natsToken != "" {
		config.NATS.Auth.Token = opts.natsToken
	}

	// Defaults for unset values
	if config.Synscan.Performance.TimeoutMS <= 0 {
		config.Synscan.Performance.TimeoutMS = 5000
	}
	if config.Synscan.Performance.RateLimit <= 0 {
		config.Synscan.Performance.RateLimit = 1000
	}

	// Batch params are internal constants (not configurable)
	config.Synscan.Performance.Batch = BatchConfig{
		Send:        64,
		Recv:        64,
		RingSize:    4096,
		IPBatchSize: 4096,
	}

	return config
}

func printUsage() {
	fmt.Printf(`meow synscan v%s

Usage:
  synscan [flags]

Flags:
  -t, --target string       Target CIDR or IP range (required in scan mode)
      --target-file string  File containing one target/range per line
  -p, --ports string        Ports to scan (default: 80,443,22,8080,8443)
  -P, --top-ports int       Scan the N most common ports (mutually exclusive with -p)
  -i, --interface string    Network interface (auto-detected if empty)
  -r, --rate-limit int      Packets per second (default: 1000)
  -T, --timeout int         Timeout in milliseconds (default: 5000)
  -c, --config string       Config file (default: config.yaml)
      --nats-url string     NATS server URL (or env: MEOW_NATS_URL)
      --nats-token string   NATS auth token (or env: MEOW_NATS_TOKEN)
      --resume string       Resume scan from token (hex 24 chars)
      --daemon              Daemon mode: wait for scan requests via NATS
  -d, --debug               Enable debug logging (or env: MEOW_DEBUG)
  -h, --help                Show help
  -v, --version             Show version

Examples:
  synscan -t 192.168.1.0/24 -p 80,443
  synscan --target-file scopes.txt -p 80,443
  synscan -t 10.0.0.1 --top-ports 100 -r 5000
  synscan -t 192.168.1-10.0/24 -p 22,80,443 --nats-url nats://localhost:4222
  synscan -c config.yaml -t 10.0.0.0/8 --timeout 10000
  synscan --daemon --nats-url nats://localhost:4222 --nats-token SECRET

Environment variables (MEOW_* namespace, shared across all meow modules):
  MEOW_NATS_URL    Alternative to --nats-url
  MEOW_NATS_TOKEN  Alternative to --nats-token
  MEOW_DEBUG       Alternative to --debug
`, version)
}

func fatal(msg string) {
	fmt.Fprintf(os.Stderr, "Error: %s\n", msg)
	os.Exit(1)
}

func fatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "Error: "+format+"\n", args...)
	os.Exit(1)
}
