// Package registry tracks live client/admin WebSocket registrations, admin
// watch relationships, and a 30-second reconnect grace window for clients.
package registry

import (
	"encoding/json"
	"log"
	"sync"
	"time"
)

// GraceWindow is how long client metadata is kept after disconnect before client_offline fires.
var GraceWindow = 30 * time.Second

// Events are emitted to the hub for admin notifications.
type Events struct {
	OnClientReconnected func(clientID string, wasOfflineMs int64)
	OnClientOffline     func(clientID string, ts int64)
}

// ClientMeta is the last-known state kept during the grace window.
type ClientMeta struct {
	InfoJSON    json.RawMessage `json:"info"`
	MonitorInfo json.RawMessage `json:"monitors,omitempty"`
	DisconnectedAt time.Time  `json:"-"`
}

// Registry is a thread-safe connection index with grace-window semantics.
type Registry struct {
	mu sync.RWMutex

	clients    map[string]*clientSlot
	admins     map[string]*adminSlot
	watchIndex map[string]map[string]*adminSlot // clientID → adminID → slot
	grace      map[string]*graceEntry

	events Events
	start  time.Time
}

type clientSlot struct {
	ID       string
	LastSeen time.Time
}

type adminSlot struct {
	ID         string
	LastSeen   time.Time
	WatchingID string // primary watch target (legacy single-watch helper)
	watching   map[string]struct{}
}

type graceEntry struct {
	meta      ClientMeta
	timer     *time.Timer
	offlineAt time.Time
}

// New creates an empty Registry.
func New(events Events) *Registry {
	return &Registry{
		clients:    make(map[string]*clientSlot),
		admins:     make(map[string]*adminSlot),
		watchIndex: make(map[string]map[string]*adminSlot),
		grace:      make(map[string]*graceEntry),
		events:     events,
		start:      time.Now(),
	}
}

// Uptime returns server uptime since registry creation.
func (r *Registry) Uptime() time.Duration {
	return time.Since(r.start)
}

// RegisterClient marks a client as live. Returns wasReconnect and offline duration
// if the client returned within the grace window.
func (r *Registry) RegisterClient(id string, info ClientMeta) (wasReconnect bool, wasOfflineMs int64) {
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()

	if g, ok := r.grace[id]; ok {
		g.timer.Stop()
		delete(r.grace, id)
		wasReconnect = true
		wasOfflineMs = now.Sub(g.offlineAt).Milliseconds()
	}

	r.clients[id] = &clientSlot{ID: id, LastSeen: now}
	if wasReconnect && r.events.OnClientReconnected != nil {
		r.events.OnClientReconnected(id, wasOfflineMs)
	}
	return wasReconnect, wasOfflineMs
}

// TouchClient updates LastSeen for a live client.
func (r *Registry) TouchClient(id string) {
	r.mu.Lock()
	if s, ok := r.clients[id]; ok {
		s.LastSeen = time.Now()
	}
	r.mu.Unlock()
}

// UnregisterClient removes a live client and starts the grace window.
// info is stored until grace expires or the client reconnects.
func (r *Registry) UnregisterClient(id string, info ClientMeta) {
	r.mu.Lock()
	delete(r.clients, id)
	info.DisconnectedAt = time.Now()

	if g, ok := r.grace[id]; ok {
		g.timer.Stop()
	}
	entry := &graceEntry{meta: info, offlineAt: info.DisconnectedAt}
	entry.timer = time.AfterFunc(GraceWindow, func() {
		r.expireGrace(id)
	})
	r.grace[id] = entry
	r.mu.Unlock()
}

func (r *Registry) expireGrace(id string) {
	r.mu.Lock()
	g, ok := r.grace[id]
	if !ok {
		r.mu.Unlock()
		return
	}
	delete(r.grace, id)
	r.mu.Unlock()

	ts := time.Now().UnixMilli()
	log.Printf("[registry] grace expired client=%s", id)
	if r.events.OnClientOffline != nil {
		r.events.OnClientOffline(id, ts)
	}
	_ = g // meta available for future use
}

// GetGraceMeta returns stored metadata for a client in grace, if any.
func (r *Registry) GetGraceMeta(id string) (ClientMeta, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	g, ok := r.grace[id]
	if !ok {
		return ClientMeta{}, false
	}
	return g.meta, true
}

// InGrace reports whether a client ID is in the reconnect grace window.
func (r *Registry) InGrace(id string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.grace[id]
	return ok
}

// RegisterAdmin adds an admin connection slot.
func (r *Registry) RegisterAdmin(id string) {
	r.mu.Lock()
	r.admins[id] = &adminSlot{
		ID:       id,
		LastSeen: time.Now(),
		watching: make(map[string]struct{}),
	}
	r.mu.Unlock()
}

// TouchAdmin updates LastSeen for an admin.
func (r *Registry) TouchAdmin(id string) {
	r.mu.Lock()
	if s, ok := r.admins[id]; ok {
		s.LastSeen = time.Now()
	}
	r.mu.Unlock()
}

// UnregisterAdmin removes an admin and clears its watch entries.
func (r *Registry) UnregisterAdmin(id string) {
	r.mu.Lock()
	a, ok := r.admins[id]
	if ok {
		for clientID := range a.watching {
			if m, exists := r.watchIndex[clientID]; exists {
				delete(m, id)
				if len(m) == 0 {
					delete(r.watchIndex, clientID)
				}
			}
		}
		delete(r.admins, id)
	}
	r.mu.Unlock()
}

// AddWatch registers admin watching clientID.
func (r *Registry) AddWatch(adminID, clientID string) {
	r.mu.Lock()
	a, ok := r.admins[adminID]
	if !ok {
		r.mu.Unlock()
		return
	}
	a.watching[clientID] = struct{}{}
	a.WatchingID = clientID
	a.LastSeen = time.Now()
	if r.watchIndex[clientID] == nil {
		r.watchIndex[clientID] = make(map[string]*adminSlot)
	}
	r.watchIndex[clientID][adminID] = a
	r.mu.Unlock()
}

// RemoveWatch clears one watch pair.
func (r *Registry) RemoveWatch(adminID, clientID string) {
	r.mu.Lock()
	if a, ok := r.admins[adminID]; ok {
		delete(a.watching, clientID)
		if a.WatchingID == clientID {
			a.WatchingID = ""
			for cid := range a.watching {
				a.WatchingID = cid
				break
			}
		}
	}
	if m, ok := r.watchIndex[clientID]; ok {
		delete(m, adminID)
		if len(m) == 0 {
			delete(r.watchIndex, clientID)
		}
	}
	r.mu.Unlock()
}

// ClearWatch removes all watches for an admin.
func (r *Registry) ClearWatch(adminID string) {
	r.mu.Lock()
	a, ok := r.admins[adminID]
	if !ok {
		r.mu.Unlock()
		return
	}
	for clientID := range a.watching {
		if m, exists := r.watchIndex[clientID]; exists {
			delete(m, adminID)
			if len(m) == 0 {
				delete(r.watchIndex, clientID)
			}
		}
	}
	a.watching = make(map[string]struct{})
	a.WatchingID = ""
	r.mu.Unlock()
}

// AdminsWatching returns admin IDs watching clientID.
func (r *Registry) AdminsWatching(clientID string) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	m, ok := r.watchIndex[clientID]
	if !ok {
		return nil
	}
	out := make([]string, 0, len(m))
	for id := range m {
		out = append(out, id)
	}
	return out
}

// ClientCount returns live (non-grace) client connections.
func (r *Registry) ClientCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.clients)
}

// AdminCount returns live admin connections.
func (r *Registry) AdminCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.admins)
}

// GraceCount returns clients waiting in the reconnect window.
func (r *Registry) GraceCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.grace)
}

// AllClientIDs returns IDs of currently connected clients.
func (r *Registry) AllClientIDs() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.clients))
	for id := range r.clients {
		out = append(out, id)
	}
	return out
}
