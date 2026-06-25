// Package heartbeat tracks WebSocket liveness via protocol ping/pong and
// read activity. Used by the relay to close connections that stop responding.
package heartbeat

import (
	"log"
	"sync"
	"time"

	"decoder-server/internal/observability"
)

const (
	// PingInterval is how often the server sends a WebSocket Ping frame.
	PingInterval = 20 * time.Second
	// PongTimeout is the maximum silence allowed after a ping before counting a miss.
	PongTimeout = 10 * time.Second
	// MaxMissedPings consecutive misses before the connection is considered dead.
	MaxMissedPings = 3
)

// Monitor tracks activity and missed pongs for one WebSocket connection.
type Monitor struct {
	mu           sync.Mutex
	lastActivity time.Time
	lastPingAt   time.Time
	missed       int
	label        string
}

// NewMonitor creates a monitor. label is used in warn logs (e.g. "client=uuid").
func NewMonitor(label string) *Monitor {
	return &Monitor{
		label:        label,
		lastActivity: time.Now(),
	}
}

// Touch resets the missed counter — call on any inbound message or Pong.
func (m *Monitor) Touch() {
	m.mu.Lock()
	m.lastActivity = time.Now()
	m.missed = 0
	m.mu.Unlock()
}

// OnPingSent is called immediately before the server writes a Ping frame.
// Returns true when the connection should be closed.
func (m *Monitor) OnPingSent() bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	if !m.lastPingAt.IsZero() && now.Sub(m.lastActivity) > PongTimeout {
		m.missed++
		if m.missed < MaxMissedPings {
			log.Printf("[heartbeat] %s missed=%d/%d", m.label, m.missed, MaxMissedPings)
		}
	}
	m.lastPingAt = now

	if m.missed >= MaxMissedPings {
		log.Printf("[heartbeat] %s closing after %d missed pongs", m.label, m.missed)
		observability.Event("relay", "heartbeat_miss",
			"conn_id", m.label,
			"type", "websocket",
			"missed_count", m.missed,
		)
		return true
	}
	return false
}

// Missed returns the current missed-pong count (for metrics/debug).
func (m *Monitor) Missed() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.missed
}

// PingPeriod returns the ticker interval for write pumps.
func PingPeriod() time.Duration {
	return PingInterval
}

// ReadDeadline returns the initial / post-pong read deadline duration.
func ReadDeadline() time.Duration {
	return PingInterval + PongTimeout
}

// IsAlive reports whether inbound activity occurred within maxSilence.
func (m *Monitor) IsAlive(maxSilence time.Duration) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return time.Since(m.lastActivity) <= maxSilence
}
