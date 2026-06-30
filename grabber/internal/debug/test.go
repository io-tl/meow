package debug

import (
	"fmt"
	"testing"
	"time"

	"meow/grabber/internal/fingerprint/grab"
	"meow/grabber/pkg/enrichment/modules"
)

// TestFingerprintDirect tests fingerprinting of a specific target
func TestFingerprintDirect(t *testing.T) {
	tests := []struct {
		name      string
		host      string
		port      int
		debug     bool
		timeout   time.Duration
		intensity int
	}{
		{
			name:      "Local HTTP",
			host:      "127.0.0.1",
			port:      80,
			debug:     false,
			timeout:   3 * time.Second,
			intensity: 3,
		},
		{
			name:      "Google HTTPS",
			host:      "google.com",
			port:      443,
			debug:     false,
			timeout:   5 * time.Second,
			intensity: 5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := grab.GrabWithOptions(
				tt.host,
				tt.port,
				tt.timeout,
				tt.intensity,
				30*time.Second,
				tt.debug,
			)

			if err != nil {
				t.Logf("Fingerprint failed for %s:%d: %v", tt.host, tt.port, err)
				return
			}

			if result == nil {
				t.Logf("No service detected on %s:%d", tt.host, tt.port)
				return
			}

			t.Logf("Service detected: %s", result.Service)
			t.Logf("Product: %s", result.Product)
			t.Logf("Version: %s", result.Version)
			t.Logf("Info: %s", result.Info)

			// Basic checks
			if result.Service == "" {
				t.Error("Service should not be empty when result is not nil")
			}
		})
	}
}

// TestEnrichmentDirect tests enrichment of specific services
func TestEnrichmentDirect(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		port    int
		service string
		domain  string
	}{
		{
			name:    "Google HTTPS",
			host:    "google.com",
			port:    443,
			service: "https",
			domain:  "google.com",
		},
		{
			name:    "HTTP Bin",
			host:    "httpbin.org",
			port:    80,
			service: "http",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			module, ok := modules.Get(tt.service)
			if !ok {
				t.Skipf("Module %s not available", tt.service)
				return
			}

			if !module.ShouldEnrich() {
				t.Skipf("Module %s is configured to skip enrichment", tt.service)
				return
			}

			var data interface{}
			var err error

			startTime := time.Now()

			if tt.domain != "" {
				data, err = module.ScanWithSNI(tt.host, tt.port, tt.domain)
				if data == nil && err == nil {
					data, err = module.Scan(tt.host, tt.port)
				}
			} else {
				data, err = module.Scan(tt.host, tt.port)
			}

			duration := time.Since(startTime)

			if err != nil {
				t.Logf("Enrichment failed for %s:%d (%s): %v", tt.host, tt.port, tt.service, err)
				return
			}

			if data == nil {
				t.Logf("No enrichment data for %s:%d (%s)", tt.host, tt.port, tt.service)
				return
			}

			t.Logf("Enrichment completed in %v", duration)
			t.Logf("Data: %+v", data)

			// Basic checks
			if data == nil {
				t.Error("Data should not be nil when enrichment succeeds")
			}
		})
	}
}

// BenchmarkFingerprint benchmarks fingerprinting performance
func BenchmarkFingerprint(b *testing.B) {
	host := "127.0.0.1"
	port := 80
	timeout := 3 * time.Second
	intensity := 3

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := grab.GrabWithOptions(host, port, timeout, intensity, 30*time.Second, false)
		if err != nil {
			b.Logf("Benchmark iteration failed: %v", err)
		}
	}
}

// BenchmarkEnrichment benchmarks enrichment performance
func BenchmarkEnrichment(b *testing.B) {
	service := "http"
	host := "httpbin.org"
	port := 80

	module, ok := modules.Get(service)
	if !ok || !module.ShouldEnrich() {
		b.Skipf("Module %s not available or disabled", service)
		return
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := module.Scan(host, port)
		if err != nil {
			b.Logf("Benchmark iteration failed: %v", err)
		}
	}
}

// ListModules lists all available modules with their state
func ListModules() {
	fmt.Println("=== Available Enrichment Modules ===")
	services := modules.ListServices()

	for name, aliases := range services {
		module, _ := modules.Get(name)
		status := "DISABLED"
		if module != nil && module.ShouldEnrich() {
			status = "ENABLED"
		}

		fmt.Printf("Module: %s (%s)\n", name, status)
		if len(aliases) > 0 {
			fmt.Printf("  Aliases: %v\n", aliases)
		}
		if module != nil {
			fmt.Printf("  Timeout: %v\n", module.DefaultTimeout())
		}
		fmt.Println()
	}
}

// QuickTest performs a quick test on a target
func QuickTest(host string, port int) {
	fmt.Printf("=== Quick Test: %s:%d ===\n", host, port)

	// Test fingerprinting
	fmt.Println("\n1. Fingerprinting:")
	result, err := grab.Grab(host, port)
	if err != nil {
		fmt.Printf("   Error: %v\n", err)
	} else if result == nil {
		fmt.Printf("   No service detected\n")
	} else {
		fmt.Printf("   Service: %s\n", result.Service)
		fmt.Printf("   Product: %s\n", result.Product)
		fmt.Printf("   Version: %s\n", result.Version)
		fmt.Printf("   Info: %s\n", result.Info)

		// Test enrichment if a service was detected
		if result.Service != "" {
			fmt.Printf("\n2. Enrichment (%s):\n", result.Service)
			module, ok := modules.Get(result.Service)
			if !ok {
				fmt.Printf("   No module available for %s\n", result.Service)
			} else if !module.ShouldEnrich() {
				fmt.Printf("   Module %s is disabled\n", result.Service)
			} else {
				data, err := module.Scan(host, port)
				if err != nil {
					fmt.Printf("   Error: %v\n", err)
				} else if data == nil {
					fmt.Printf("   No enrichment data\n")
				} else {
					fmt.Printf("   Data: %+v\n", data)
				}
			}
		}
	}

	fmt.Println("\n=== Test Complete ===")
}

// RunTestsFromCLI runs the tests from the command line
func RunTestsFromCLI(args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: grab debug test <command>")
		fmt.Println("\nCommands:")
		fmt.Println("  fingerprint <host> <port>  Test fingerprinting")
		fmt.Println("  enrichment <host> <port> <service> [domain]  Test enrichment")
		fmt.Println("  modules                    List available modules")
		fmt.Println("  quick <host> <port>        Quick test (fingerprint + enrichment)")
		fmt.Println("  benchmark                  Run benchmarks")
		return
	}

	command := args[0]

	switch command {
	case "fingerprint":
		if len(args) < 3 {
			fmt.Println("Usage: grab debug test fingerprint <host> <port>")
			return
		}
		host := args[1]
		port := parseInt(args[2])
		if port == 0 {
			fmt.Println("Invalid port number")
			return
		}

		result, err := grab.Grab(host, port)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
		} else if result == nil {
			fmt.Println("No service detected")
		} else {
			fmt.Printf("Service: %s\n", result.Service)
			fmt.Printf("Product: %s\n", result.Product)
			fmt.Printf("Version: %s\n", result.Version)
			fmt.Printf("Info: %s\n", result.Info)
		}

	case "enrichment":
		if len(args) < 4 {
			fmt.Println("Usage: grab debug test enrichment <host> <port> <service> [domain]")
			return
		}
		host := args[1]
		port := parseInt(args[2])
		service := args[3]
		var domain string
		if len(args) > 4 {
			domain = args[4]
		}

		module, ok := modules.Get(service)
		if !ok {
			fmt.Printf("Module %s not available\n", service)
			return
		}

		var data interface{}
		var err error

		if domain != "" {
			data, err = module.ScanWithSNI(host, port, domain)
		} else {
			data, err = module.Scan(host, port)
		}

		if err != nil {
			fmt.Printf("Error: %v\n", err)
		} else if data == nil {
			fmt.Println("No enrichment data")
		} else {
			fmt.Printf("Data: %+v\n", data)
		}

	case "modules":
		ListModules()

	case "quick":
		if len(args) < 3 {
			fmt.Println("Usage: grab debug test quick <host> <port>")
			return
		}
		host := args[1]
		port := parseInt(args[2])
		if port == 0 {
			fmt.Println("Invalid port number")
			return
		}
		QuickTest(host, port)

	case "benchmark":
		fmt.Println("Running benchmarks...")
		// Run the benchmarks manually
		fmt.Println("BenchmarkFingerprint:")
		b := &testing.B{}
		BenchmarkFingerprint(b)

		fmt.Println("\nBenchmarkEnrichment:")
		b = &testing.B{}
		BenchmarkEnrichment(b)

	default:
		fmt.Printf("Unknown command: %s\n", command)
	}
}

func parseInt(s string) int {
	var result int
	fmt.Sscanf(s, "%d", &result)
	return result
}
