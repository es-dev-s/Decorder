package main

import (
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	ipConnLimitPerMinute   = 5
	uuidReconnectPerMinute = 3
	uuidReconnectBackoff   = 60 * time.Second
)

// ipConnLimiter caps new WebSocket upgrades per source IP per minute.
type ipConnLimiter struct {
	mu       sync.Mutex
	attempts map[string][]time.Time
}

var globalIPConnLimiter = &ipConnLimiter{attempts: make(map[string][]time.Time)}

func (l *ipConnLimiter) Allow(ip string) bool {
	now := time.Now()
	cutoff := now.Add(-time.Minute)
	l.mu.Lock()
	defer l.mu.Unlock()
	history := l.attempts[ip]
	kept := history[:0]
	for _, t := range history {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= ipConnLimitPerMinute {
		l.attempts[ip] = kept
		return false
	}
	l.attempts[ip] = append(kept, now)
	return true
}

// uuidReconnectLimiter caps reconnect attempts per client UUID per minute.
type uuidReconnectLimiter struct {
	mu           sync.Mutex
	attempts     map[string][]time.Time
	backoffUntil map[string]time.Time
}

var globalUUIDReconnectLimiter = &uuidReconnectLimiter{
	attempts:     make(map[string][]time.Time),
	backoffUntil: make(map[string]time.Time),
}

func (l *uuidReconnectLimiter) Allow(uuid string) (ok bool, retryAfter time.Duration) {
	now := time.Now()
	cutoff := now.Add(-time.Minute)
	l.mu.Lock()
	defer l.mu.Unlock()

	if until, blocked := l.backoffUntil[uuid]; blocked && now.Before(until) {
		return false, until.Sub(now)
	}
	delete(l.backoffUntil, uuid)

	history := l.attempts[uuid]
	kept := history[:0]
	for _, t := range history {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= uuidReconnectPerMinute {
		l.backoffUntil[uuid] = now.Add(uuidReconnectBackoff)
		l.attempts[uuid] = kept
		return false, uuidReconnectBackoff
	}
	l.attempts[uuid] = append(kept, now)
	return true, 0
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.Index(xff, ","); i >= 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func authDebug(format string, args ...any) {
	if authDebugEnabled() {
		log.Printf(format, args...)
	}
}

func authDebugEnabled() bool {
	return os.Getenv("DECODER_DEBUG") == "1"
}

// IPConnRateLimitMiddleware limits new WebSocket connections per IP per minute.
func IPConnRateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		if !globalIPConnLimiter.Allow(ip) {
			log.Printf("[ratelimit] ip=%s exceeded %d connections/minute", ip, ipConnLimitPerMinute)
			http.Error(w, "too many connections", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}
