package scanner

import (
	"context"
	"math/rand"
	"time"

	"golang.org/x/time/rate"
)

// JitteredLimiter combines rate limiting with timing jitter
type JitteredLimiter struct {
	limiter   *rate.Limiter
	jitterMin time.Duration
	jitterMax time.Duration
	rng       *rand.Rand
}

// NewJitteredLimiter creates a rate limiter with jitter
func NewJitteredLimiter(baseRate int, jitterMin, jitterMax time.Duration) *JitteredLimiter {
	burst := baseRate / 10
	if burst < 1 {
		burst = 1
	}

	return &JitteredLimiter{
		limiter:   rate.NewLimiter(rate.Limit(baseRate), burst),
		jitterMin: jitterMin,
		jitterMax: jitterMax,
		rng:       rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// Wait applies rate limiting + random jitter
func (j *JitteredLimiter) Wait(ctx context.Context) error {
	// Base rate limiting
	if err := j.limiter.Wait(ctx); err != nil {
		return err
	}

	// Add random jitter
	if j.jitterMax > 0 {
		jitterRange := j.jitterMax - j.jitterMin
		jitter := j.jitterMin + time.Duration(j.rng.Int63n(int64(jitterRange)))

		select {
		case <-time.After(jitter):
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return nil
}
