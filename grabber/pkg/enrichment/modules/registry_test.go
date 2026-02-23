package modules

import (
	"testing"
	"time"
)

// testModule is a minimal ServiceModule for tests.
type testModule struct {
	BaseModule
	scanResult interface{}
	scanErr    error
	sniResult  interface{}
	sniErr     error
}

func (m *testModule) Scan(ip string, port int) (interface{}, error) {
	return m.scanResult, m.scanErr
}

func (m *testModule) ScanWithSNI(ip string, port int, domain string) (interface{}, error) {
	if m.sniResult != nil || m.sniErr != nil {
		return m.sniResult, m.sniErr
	}
	return nil, nil
}

func newTestModule(name string, aliases []string, shouldEnrich bool) *testModule {
	return &testModule{
		BaseModule: NewBaseModule(name, aliases, shouldEnrich, 10*time.Second),
		scanResult: map[string]string{"protocol": name},
	}
}

func TestRegister_And_Get(t *testing.T) {
	restore := RestoreRegistryForTesting()
	defer restore()
	ResetRegistryForTesting()

	mod := newTestModule("mytest", nil, true)
	Register(mod)

	got, ok := Get("mytest")
	if !ok {
		t.Fatal("expected module to be found")
	}
	if got.Name() != "mytest" {
		t.Errorf("Name() = %q, want %q", got.Name(), "mytest")
	}
}

func TestGet_ByAlias(t *testing.T) {
	restore := RestoreRegistryForTesting()
	defer restore()
	ResetRegistryForTesting()

	mod := newTestModule("myproto", []string{"alias1", "alias2"}, true)
	Register(mod)

	got, ok := Get("alias1")
	if !ok {
		t.Fatal("expected module found by alias")
	}
	if got.Name() != "myproto" {
		t.Errorf("Name() = %q, want %q", got.Name(), "myproto")
	}

	got2, ok := Get("alias2")
	if !ok {
		t.Fatal("expected module found by second alias")
	}
	if got2.Name() != "myproto" {
		t.Errorf("Name() = %q, want %q", got2.Name(), "myproto")
	}
}

func TestGet_CaseInsensitive(t *testing.T) {
	restore := RestoreRegistryForTesting()
	defer restore()
	ResetRegistryForTesting()

	Register(newTestModule("ssh", nil, true))

	_, ok := Get("SSH")
	if !ok {
		t.Error("expected case-insensitive match for 'SSH'")
	}
	_, ok = Get("Ssh")
	if !ok {
		t.Error("expected case-insensitive match for 'Ssh'")
	}
}

func TestGet_NotFound(t *testing.T) {
	restore := RestoreRegistryForTesting()
	defer restore()
	ResetRegistryForTesting()

	_, ok := Get("nonexistent")
	if ok {
		t.Error("expected not found")
	}
}

func TestGetAll_NoDuplicates(t *testing.T) {
	restore := RestoreRegistryForTesting()
	defer restore()
	ResetRegistryForTesting()

	Register(newTestModule("proto1", []string{"a1", "a2", "a3"}, true))
	Register(newTestModule("proto2", nil, true))

	all := GetAll()
	if len(all) != 2 {
		t.Errorf("got %d modules, want 2 (no duplicates)", len(all))
	}
}

func TestScanService_Existing(t *testing.T) {
	restore := RestoreRegistryForTesting()
	defer restore()
	ResetRegistryForTesting()

	Register(newTestModule("testproto", nil, true))

	result, err := ScanService("testproto", "1.2.3.4", 80)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Error("expected non-nil result")
	}
}

func TestScanService_NotFound(t *testing.T) {
	restore := RestoreRegistryForTesting()
	defer restore()
	ResetRegistryForTesting()

	_, err := ScanService("unknown", "1.2.3.4", 80)
	if err == nil {
		t.Error("expected error for unknown module")
	}
}

func TestScanServiceWithSNI_WithDomain(t *testing.T) {
	restore := RestoreRegistryForTesting()
	defer restore()
	ResetRegistryForTesting()

	mod := newTestModule("sniproto", nil, true)
	mod.sniResult = "sni-data"
	Register(mod)

	result, err := ScanServiceWithSNI("sniproto", "1.2.3.4", 443, "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "sni-data" {
		t.Errorf("got %v, want %q", result, "sni-data")
	}
}

func TestScanServiceWithSNI_Fallback(t *testing.T) {
	restore := RestoreRegistryForTesting()
	defer restore()
	ResetRegistryForTesting()

	mod := newTestModule("fallbackproto", nil, true)
	// ScanWithSNI returns nil, nil -> should fall back to Scan
	Register(mod)

	result, err := ScanServiceWithSNI("fallbackproto", "1.2.3.4", 80, "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Error("expected fallback to Scan()")
	}
}

func TestScanServiceWithSNI_NotFound(t *testing.T) {
	restore := RestoreRegistryForTesting()
	defer restore()
	ResetRegistryForTesting()

	_, err := ScanServiceWithSNI("nonexistent", "1.2.3.4", 80, "")
	if err == nil {
		t.Error("expected error for unknown module")
	}
}

func TestShouldEnrich_Enrichable(t *testing.T) {
	restore := RestoreRegistryForTesting()
	defer restore()
	ResetRegistryForTesting()

	Register(newTestModule("enrichable", nil, true))
	if !ShouldEnrich("enrichable") {
		t.Error("expected true")
	}
}

func TestShouldEnrich_NonEnrichable(t *testing.T) {
	restore := RestoreRegistryForTesting()
	defer restore()
	ResetRegistryForTesting()

	Register(newTestModule("noenrich", nil, false))
	if ShouldEnrich("noenrich") {
		t.Error("expected false")
	}
}

func TestShouldEnrich_Unknown(t *testing.T) {
	restore := RestoreRegistryForTesting()
	defer restore()
	ResetRegistryForTesting()

	if ShouldEnrich("unknown_service") {
		t.Error("expected false for unknown service")
	}
}

func TestListServices(t *testing.T) {
	restore := RestoreRegistryForTesting()
	defer restore()
	ResetRegistryForTesting()

	Register(newTestModule("proto1", []string{"a", "b"}, true))
	Register(newTestModule("proto2", nil, true))

	services := ListServices()
	if len(services) != 2 {
		t.Errorf("got %d services, want 2", len(services))
	}
	if aliases, ok := services["proto1"]; !ok || len(aliases) != 2 {
		t.Errorf("proto1 aliases = %v", aliases)
	}
}
