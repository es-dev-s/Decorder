package main

import (
	"log"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// DeviceLimiter maintains a per-device-CN token bucket limiter.
// Each device gets 30 requests/second with a burst of 30.
type DeviceLimiter struct {
	mu       sync.Mutex
	limiters map[string]*rate.Limiter
	lastSeen map[string]time.Time
}

var globalDeviceLimiter = &DeviceLimiter{
	limiters: make(map[string]*rate.Limiter),
	lastSeen: make(map[string]time.Time),
}

func init() {
	// Prune idle entries once per minute to prevent unbounded map growth.
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for range t.C {
			globalDeviceLimiter.prune(5 * time.Minute)
		}
	}()
}

func (d *DeviceLimiter) Get(cn string) *rate.Limiter {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.lastSeen[cn] = time.Now()
	if l, ok := d.limiters[cn]; ok {
		return l
	}
	l := rate.NewLimiter(rate.Every(time.Second), 30)
	d.limiters[cn] = l
	return l
}

func (d *DeviceLimiter) prune(idle time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()
	cutoff := time.Now().Add(-idle)
	for cn, t := range d.lastSeen {
		if t.Before(cutoff) {
			delete(d.limiters, cn)
			delete(d.lastSeen, cn)
		}
	}
}

// RateLimitMiddleware rejects upgrade requests that exceed the per-device limit.
// It reads the cert CN (set after mTLS) or falls back to remote address.
func RateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cn := PeerCertCN(r)
		if cn == "" {
			cn = r.RemoteAddr
		}
		if !globalDeviceLimiter.Get(cn).Allow() {
			log.Printf("[ratelimit] %s exceeded limit", cn)
			Audit(AuditEvent{
				EventType:  "client_rate_limited",
				RemoteAddr: r.RemoteAddr,
				CertCN:     cn,
				Outcome:    "deny",
				Reason:     "rate limit exceeded",
			})
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}
