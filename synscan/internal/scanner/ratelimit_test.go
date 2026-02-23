package scanner

import (
	"context"
	"testing"
	"time"
)

func TestNewJitteredLimiter_Basic(t *testing.T) {
	l := NewJitteredLimiter(1000, 0, 0)
	if l == nil {
		t.Fatal("NewJitteredLimiter returned nil")
	}
}

func TestNewJitteredLimiter_BurstCalculation(t *testing.T) {
	// burst = baseRate / 10
	l := NewJitteredLimiter(100, 0, 0)
	if l.limiter.Burst() != 10 {
		t.Errorf("burst: expected 10, got %d", l.limiter.Burst())
	}
}

func TestNewJitteredLimiter_BurstMinimumOne(t *testing.T) {
	// baseRate=5, burst=5/10=0 → clamped to 1
	l := NewJitteredLimiter(5, 0, 0)
	if l.limiter.Burst() != 1 {
		t.Errorf("burst should be at least 1, got %d", l.limiter.Burst())
	}
}

func TestNewJitteredLimiter_BurstMinOneForZeroRate(t *testing.T) {
	// Edge case: baseRate=0
	l := NewJitteredLimiter(0, 0, 0)
	if l.limiter.Burst() < 1 {
		t.Errorf("burst should be at least 1, got %d", l.limiter.Burst())
	}
}

func TestJitteredLimiter_WaitReturnsNilWithoutJitter(t *testing.T) {
	l := NewJitteredLimiter(10000, 0, 0)
	ctx := context.Background()

	err := l.Wait(ctx)
	if err != nil {
		t.Errorf("Wait should return nil without jitter, got %v", err)
	}
}

func TestJitteredLimiter_WaitRespectsContext(t *testing.T) {
	l := NewJitteredLimiter(1, 0, 0) // Very slow rate (1 PPS)
	ctx, cancel := context.WithCancel(context.Background())

	// First call consumes the burst token
	_ = l.Wait(ctx)

	// Cancel context before next Wait
	cancel()

	err := l.Wait(ctx)
	if err == nil {
		t.Error("Wait should return error when context is cancelled")
	}
}

func TestJitteredLimiter_WaitWithJitter(t *testing.T) {
	// Jitter between 1ms and 5ms
	l := NewJitteredLimiter(100000, 1*time.Millisecond, 5*time.Millisecond)
	ctx := context.Background()

	start := time.Now()
	err := l.Wait(ctx)
	elapsed := time.Since(start)

	if err != nil {
		t.Errorf("Wait should return nil, got %v", err)
	}

	// Should take at least jitterMin (1ms)
	if elapsed < 1*time.Millisecond {
		t.Errorf("expected at least 1ms jitter, got %v", elapsed)
	}
}

func TestJitteredLimiter_JitterContextCancel(t *testing.T) {
	// Long jitter that we cancel
	l := NewJitteredLimiter(100000, 100*time.Millisecond, 1*time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()

	err := l.Wait(ctx)
	if err == nil {
		t.Error("expected error when context cancelled during jitter")
	}
}

func TestJitteredLimiter_RateLimiting(t *testing.T) {
	// 100 PPS = 10ms between packets
	l := NewJitteredLimiter(100, 0, 0)
	ctx := context.Background()

	// Warm up: consume burst tokens
	for i := 0; i < 10; i++ {
		_ = l.Wait(ctx)
	}

	// Time 5 calls after burst exhaustion
	start := time.Now()
	for i := 0; i < 5; i++ {
		if err := l.Wait(ctx); err != nil {
			t.Fatalf("Wait error: %v", err)
		}
	}
	elapsed := time.Since(start)

	// 5 calls at 100 PPS ≈ 50ms minimum
	if elapsed < 30*time.Millisecond {
		t.Errorf("rate limiting too fast: 5 calls took only %v (expected ~50ms)", elapsed)
	}
}

func TestJitteredLimiter_NoJitterByDefault(t *testing.T) {
	l := NewJitteredLimiter(10000, 0, 0)
	if l.jitterMax != 0 {
		t.Errorf("jitterMax should be 0, got %v", l.jitterMax)
	}
	if l.jitterMin != 0 {
		t.Errorf("jitterMin should be 0, got %v", l.jitterMin)
	}
}
