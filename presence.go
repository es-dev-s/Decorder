package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// PresenceEvent mirrors the Rust client payload.
type PresenceEvent struct {
	ID          string `json:"id"`
	ClientID    string `json:"client_id"`
	Hostname    string `json:"hostname"`
	Username    string `json:"username"`
	Kind        string `json:"kind"`
	AtMs        int64  `json:"at_ms"`
	SessionID   uint32 `json:"session_id"`
	BootID      string `json:"boot_id"`
	Source      string `json:"source"`
	LoginAtMs   *int64 `json:"login_at_ms,omitempty"`
}

type presenceStore struct {
	mu    sync.Mutex
	path  string
	seen  map[string]struct{}
	events []PresenceEvent
}

func newPresenceStore() *presenceStore {
	dir := os.Getenv("DECODER_DATA_DIR")
	if dir == "" {
		dir = "."
	}
	path := filepath.Join(dir, "presence-log.json")
	ps := &presenceStore{
		path:  path,
		seen:  make(map[string]struct{}),
		events: []PresenceEvent{},
	}
	ps.load()
	return ps
}

func (ps *presenceStore) load() {
	raw, err := os.ReadFile(ps.path)
	if err != nil {
		return
	}
	var stored []PresenceEvent
	if err := json.Unmarshal(raw, &stored); err != nil {
		return
	}
	ps.events = stored
	for _, e := range stored {
		ps.seen[e.ID] = struct{}{}
	}
}

func (ps *presenceStore) save() {
	// Snapshot events under lock, then release before doing slow disk I/O.
	// This prevents ingest() and list() from blocking on file writes.
	ps.mu.Lock()
	snapshot := make([]PresenceEvent, len(ps.events))
	copy(snapshot, ps.events)
	ps.mu.Unlock()

	raw, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return
	}
	tmp := ps.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return
	}
	_ = os.Rename(tmp, ps.path)
}

func (ps *presenceStore) ingest(events []PresenceEvent) int {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	added := 0
	for _, e := range events {
		if e.ID == "" {
			continue
		}
		if _, ok := ps.seen[e.ID]; ok {
			continue
		}
		ps.seen[e.ID] = struct{}{}
		ps.events = append(ps.events, e)
		added++
		log.Printf("    presence %s %s@%s kind=%s at=%d source=%s",
			e.ClientID, e.Username, e.Hostname, e.Kind, e.AtMs, e.Source)
	}
	if added > 0 {
		go ps.save()
	}
	return added
}

func (ps *presenceStore) list(clientID string, fromMs, toMs int64) []PresenceEvent {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	out := make([]PresenceEvent, 0)
	for _, e := range ps.events {
		if clientID != "" && e.ClientID != clientID {
			continue
		}
		if fromMs > 0 && e.AtMs < fromMs {
			continue
		}
		if toMs > 0 && e.AtMs > toMs {
			continue
		}
		out = append(out, e)
	}
	return out
}

func (h *hub) handlePresenceSync(clientID string, msg map[string]any) {
	rawEvents, ok := msg["events"].([]any)
	if !ok {
		return
	}
	batch := make([]PresenceEvent, 0, len(rawEvents))
	for _, item := range rawEvents {
		b, err := json.Marshal(item)
		if err != nil {
			continue
		}
		var ev PresenceEvent
		if err := json.Unmarshal(b, &ev); err != nil {
			continue
		}
		if ev.ClientID == "" {
			ev.ClientID = clientID
		}
		batch = append(batch, ev)
	}
	if h.presence.ingest(batch) > 0 {
		h.broadcastPresence(batch)
	}
}

func (h *hub) broadcastPresence(events []PresenceEvent) {
	payload, err := json.Marshal(map[string]any{
		"type":      "presence",
		"events":    events,
		"server_at": time.Now().UnixMilli(),
	})
	if err != nil {
		return
	}
	h.broadcastPresenceToAdmins(payload)
}

func (h *hub) handleAPIPresence(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	clientID := r.URL.Query().Get("client_id")
	fromMs, _ := strconv.ParseInt(r.URL.Query().Get("from_ms"), 10, 64)
	toMs, _ := strconv.ParseInt(r.URL.Query().Get("to_ms"), 10, 64)

	list := h.presence.list(clientID, fromMs, toMs)
	_ = json.NewEncoder(w).Encode(list)
}
