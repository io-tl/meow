package modules

// ResetRegistryForTesting clears the global registry. Must be called in tests
// that need an empty registry to avoid side effects from init() registrations.
func ResetRegistryForTesting() {
	globalRegistry.mu.Lock()
	defer globalRegistry.mu.Unlock()
	globalRegistry.modules = make(map[string]ServiceModule)
}

// RestoreRegistryForTesting copies the current state so it can be restored later.
func RestoreRegistryForTesting() func() {
	globalRegistry.mu.RLock()
	saved := make(map[string]ServiceModule, len(globalRegistry.modules))
	for k, v := range globalRegistry.modules {
		saved[k] = v
	}
	globalRegistry.mu.RUnlock()

	return func() {
		globalRegistry.mu.Lock()
		defer globalRegistry.mu.Unlock()
		globalRegistry.modules = saved
	}
}
