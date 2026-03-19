package network

import (
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Token-bucket rate limiter per remote IP.
type RateLimiter struct {
	rps   float64
	burst float64
	bkts  sync.Map // key: ip string, value: *bucket
}

type bucket struct {
	mu     sync.Mutex
	tokens float64
	last   time.Time
}

// NewRateLimiter creates a limiter with requests-per-second and burst capacity.
func NewRateLimiter(rps float64, burst float64) *RateLimiter {
	rl := &RateLimiter{rps: rps, burst: burst}
	go rl.cleanupLoop()
	return rl
}

// Wrap applies limiting middleware to a handler.
func (rl *RateLimiter) Wrap(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		if !rl.allow(ip) {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}

func (rl *RateLimiter) allow(ip string) bool {
	if rl == nil || rl.rps <= 0 {
		return true
	}
	val, _ := rl.bkts.LoadOrStore(ip, &bucket{
		tokens: rl.burst,
		last:   time.Now(),
	})
	b := val.(*bucket)
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(b.last).Seconds()
	b.last = now
	b.tokens = minFloat(rl.burst, b.tokens+elapsed*rl.rps)
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// AllowKey applies token-bucket limiting for an arbitrary key namespace
// (for example client ID or receiver ID).
func (rl *RateLimiter) AllowKey(key string) bool {
	return rl.allow(key)
}

// cleanupLoop removes old buckets to prevent memory leaks
func (rl *RateLimiter) cleanupLoop() {
	ticker := time.NewTicker(10 * time.Minute)
	for range ticker.C {
		now := time.Now()
		rl.bkts.Range(func(key, value interface{}) bool {
			b := value.(*bucket)
			b.mu.Lock()
			// If unused for 1 hour, delete
			if now.Sub(b.last) > 1*time.Hour {
				rl.bkts.Delete(key)
			}
			b.mu.Unlock()
			return true
		})
	}
}

func clientIP(r *http.Request) string {
	// If behind a trusted reverse proxy, X-Forwarded-For handling could be added carefully.
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

// ParseRateEnv returns (rps, burst) from strings; falls back to defaults on error.
func ParseRateEnv(rpsStr, burstStr string, defRps, defBurst float64) (float64, float64) {
	rps := defRps
	if v, err := strconv.ParseFloat(rpsStr, 64); err == nil && v > 0 {
		rps = v
	}
	burst := defBurst
	if v, err := strconv.ParseFloat(burstStr, 64); err == nil && v > 0 {
		burst = v
	}
	return rps, burst
}
