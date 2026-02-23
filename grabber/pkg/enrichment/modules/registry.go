package modules

import (
	"fmt"
	"strings"
	"sync"
)

// Registry manages service module registration and discovery
type Registry struct {
	modules map[string]ServiceModule // map[serviceName]module
	mu      sync.RWMutex
}

var globalRegistry = &Registry{
	modules: make(map[string]ServiceModule),
}

// Register registers a service module in the global registry
func Register(module ServiceModule) {
	globalRegistry.mu.Lock()
	defer globalRegistry.mu.Unlock()

	// Register module under its primary name
	name := strings.ToLower(module.Name())
	globalRegistry.modules[name] = module

	// Also register under all aliases
	for _, alias := range module.Aliases() {
		alias = strings.ToLower(alias)
		globalRegistry.modules[alias] = module
	}
}

// Get retrieves a module by its name or alias
func Get(serviceName string) (ServiceModule, bool) {
	globalRegistry.mu.RLock()
	defer globalRegistry.mu.RUnlock()

	module, ok := globalRegistry.modules[strings.ToLower(serviceName)]
	return module, ok
}

// GetAll returns all registered modules (without duplicates)
func GetAll() []ServiceModule {
	globalRegistry.mu.RLock()
	defer globalRegistry.mu.RUnlock()

	seen := make(map[string]bool)
	var modules []ServiceModule

	for _, module := range globalRegistry.modules {
		name := module.Name()
		if !seen[name] {
			seen[name] = true
			modules = append(modules, module)
		}
	}

	return modules
}

// ScanService is a utility function that finds and executes the right module
func ScanService(serviceName string, ip string, port int) (interface{}, error) {
	module, ok := Get(serviceName)
	if !ok {
		return nil, fmt.Errorf("no module found for service '%s'", serviceName)
	}

	return module.Scan(ip, port)
}

// ScanServiceWithSNI scans a service with SNI (Server Name Indication) support
// Currently supported only for HTTP/HTTPS
func ScanServiceWithSNI(serviceName string, ip string, port int, domain string) (interface{}, error) {
	module, ok := Get(serviceName)
	if !ok {
		return nil, fmt.Errorf("no module found for service '%s'", serviceName)
	}

	// Try SNI-enabled scan first
	result, err := module.ScanWithSNI(ip, port, domain)
	if result != nil || err != nil {
		return result, err
	}

	// Fallback: use regular scan
	return module.Scan(ip, port)
}

// ShouldEnrich checks if a service should be enriched
func ShouldEnrich(serviceName string) bool {
	module, ok := Get(serviceName)
	if !ok {
		return false // Unknown service = no enrichment
	}
	return module.ShouldEnrich()
}

// ListServices returns the list of available services with their aliases
func ListServices() map[string][]string {
	result := make(map[string][]string)

	for _, module := range GetAll() {
		result[module.Name()] = module.Aliases()
	}

	return result
}
