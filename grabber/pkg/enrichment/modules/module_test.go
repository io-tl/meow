package modules

import (
	"testing"
	"time"
)

func TestNewBaseModule_Fields(t *testing.T) {
	bm := NewBaseModule("ssh", []string{"ssh2"}, true, 10*time.Second)
	if bm.Name() != "ssh" {
		t.Errorf("Name() = %q, want %q", bm.Name(), "ssh")
	}
	aliases := bm.Aliases()
	if len(aliases) != 1 || aliases[0] != "ssh2" {
		t.Errorf("Aliases() = %v", aliases)
	}
	if !bm.ShouldEnrich() {
		t.Error("ShouldEnrich() = false, want true")
	}
	if bm.DefaultTimeout() != 10*time.Second {
		t.Errorf("DefaultTimeout() = %v, want 10s", bm.DefaultTimeout())
	}
}

func TestBaseModule_DefaultTimeout_Zero(t *testing.T) {
	bm := NewBaseModule("test", nil, true, 0)
	if bm.DefaultTimeout() != 15*time.Second {
		t.Errorf("DefaultTimeout() = %v, want 15s (default)", bm.DefaultTimeout())
	}
}

func TestBaseModule_DefaultTimeout_Custom(t *testing.T) {
	bm := NewBaseModule("test", nil, true, 5*time.Second)
	if bm.DefaultTimeout() != 5*time.Second {
		t.Errorf("DefaultTimeout() = %v, want 5s", bm.DefaultTimeout())
	}
}

func TestBaseModule_ScanWithSNI_Default(t *testing.T) {
	bm := NewBaseModule("test", nil, true, 10*time.Second)
	result, err := bm.ScanWithSNI("1.2.3.4", 80, "example.com")
	if result != nil {
		t.Errorf("result = %v, want nil", result)
	}
	if err != nil {
		t.Errorf("err = %v, want nil", err)
	}
}

func TestBaseModule_Name(t *testing.T) {
	bm := NewBaseModule("ftp", []string{"ftp-data"}, true, 10*time.Second)
	if bm.Name() != "ftp" {
		t.Errorf("Name() = %q, want %q", bm.Name(), "ftp")
	}
}

func TestBaseModule_Aliases(t *testing.T) {
	bm := NewBaseModule("smtp", []string{"smtps", "submission"}, true, 10*time.Second)
	aliases := bm.Aliases()
	if len(aliases) != 2 {
		t.Fatalf("got %d aliases, want 2", len(aliases))
	}
	if aliases[0] != "smtps" || aliases[1] != "submission" {
		t.Errorf("Aliases() = %v", aliases)
	}
}

func TestBaseModule_ShouldEnrich_True(t *testing.T) {
	bm := NewBaseModule("http", nil, true, 10*time.Second)
	if !bm.ShouldEnrich() {
		t.Error("ShouldEnrich() = false, want true")
	}
}

func TestBaseModule_ShouldEnrich_False(t *testing.T) {
	bm := NewBaseModule("modbus", nil, false, 10*time.Second)
	if bm.ShouldEnrich() {
		t.Error("ShouldEnrich() = true, want false")
	}
}

func TestBaseModule_NilAliases(t *testing.T) {
	bm := NewBaseModule("test", nil, true, 10*time.Second)
	aliases := bm.Aliases()
	if aliases != nil {
		t.Errorf("Aliases() = %v, want nil", aliases)
	}
}
