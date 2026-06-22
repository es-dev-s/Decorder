package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

const (
	screenshotMaxBodyBytes = 8 << 20 // 8 MiB
	screenshotWorkers      = 4
	screenshotIngestQueue  = 1024
)

// ScreenshotMeta is stored in the index and sent to admins.
type ScreenshotMeta struct {
	ID           string `json:"id"`
	ClientID     string `json:"client_id"`
	Hostname     string `json:"hostname"`
	Username     string `json:"username"`
	MonitorIndex uint32 `json:"monitor_index"`
	AtMs         int64  `json:"at_ms"`
	Width        uint32 `json:"width"`
	Height       uint32 `json:"height"`
}

type screenshotIngestJob struct {
	meta ScreenshotMeta
	data []byte
}

type screenshotStore struct {
	mu        sync.RWMutex
	dir       string
	indexPath string
	seen      map[string]struct{}
	items     []ScreenshotMeta
	ingestCh  chan screenshotIngestJob
	onSaved   func(ScreenshotMeta)
}

func newScreenshotStore(onSaved func(ScreenshotMeta)) *screenshotStore {
	dir := os.Getenv("DECODER_DATA_DIR")
	if dir == "" {
		dir = "."
	}
	root := filepath.Join(dir, "screenshots")
	_ = os.MkdirAll(root, 0o755)

	s := &screenshotStore{
		dir:       root,
		indexPath: filepath.Join(dir, "screenshots-index.json"),
		seen:      make(map[string]struct{}),
		items:     []ScreenshotMeta{},
		ingestCh:  make(chan screenshotIngestJob, screenshotIngestQueue),
		onSaved:   onSaved,
	}
	s.load()
	for i := 0; i < screenshotWorkers; i++ {
		go s.worker()
	}
	return s
}

func (s *screenshotStore) worker() {
	for job := range s.ingestCh {
		if s.process(job.meta, job.data) && s.onSaved != nil {
			s.onSaved(job.meta)
		}
	}
}

func (s *screenshotStore) load() {
	raw, err := os.ReadFile(s.indexPath)
	if err != nil {
		return
	}
	var stored []ScreenshotMeta
	if err := json.Unmarshal(raw, &stored); err != nil {
		return
	}
	s.items = stored
	for _, item := range stored {
		s.seen[item.ID] = struct{}{}
	}
}

func (s *screenshotStore) saveIndex() {
	s.mu.RLock()
	raw, err := json.MarshalIndent(s.items, "", "  ")
	s.mu.RUnlock()
	if err != nil {
		return
	}
	tmp := s.indexPath + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return
	}
	_ = os.Rename(tmp, s.indexPath)
}

func (s *screenshotStore) filePath(meta ScreenshotMeta) string {
	t := time.UnixMilli(meta.AtMs)
	return filepath.Join(
		s.dir,
		meta.ClientID,
		fmt.Sprintf("%04d", t.Year()),
		fmt.Sprintf("%02d", int(t.Month())),
		fmt.Sprintf("%02d", t.Day()),
		fmt.Sprintf("%s_m%d.jpg", meta.ID, meta.MonitorIndex),
	)
}

func (s *screenshotStore) process(meta ScreenshotMeta, data []byte) bool {
	if meta.ID == "" || len(data) == 0 {
		return false
	}

	s.mu.Lock()
	if _, ok := s.seen[meta.ID]; ok {
		s.mu.Unlock()
		return false
	}
	s.seen[meta.ID] = struct{}{}
	s.mu.Unlock()

	path := s.filePath(meta)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		log.Printf("    screenshot mkdir: %v", err)
		s.unseen(meta.ID)
		return false
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		log.Printf("    screenshot write: %v", err)
		s.unseen(meta.ID)
		return false
	}
	if err := os.Rename(tmp, path); err != nil {
		log.Printf("    screenshot rename: %v", err)
		_ = os.Remove(tmp)
		s.unseen(meta.ID)
		return false
	}

	s.mu.Lock()
	s.items = append(s.items, meta)
	s.mu.Unlock()
	go s.saveIndex()

	log.Printf("    screenshot %s %s@%s monitor=%d at=%d (%dx%d)",
		meta.ClientID, meta.Username, meta.Hostname, meta.MonitorIndex, meta.AtMs, meta.Width, meta.Height)
	return true
}

func (s *screenshotStore) unseen(id string) {
	s.mu.Lock()
	delete(s.seen, id)
	s.mu.Unlock()
}

func (s *screenshotStore) enqueue(meta ScreenshotMeta, data []byte) bool {
	job := screenshotIngestJob{meta: meta, data: append([]byte(nil), data...)}
	select {
	case s.ingestCh <- job:
		return true
	default:
		return false
	}
}

func (s *screenshotStore) list(clientID string, fromMs, toMs int64) []ScreenshotMeta {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]ScreenshotMeta, 0)
	for _, item := range s.items {
		if clientID != "" && item.ClientID != clientID {
			continue
		}
		if fromMs > 0 && item.AtMs < fromMs {
			continue
		}
		if toMs > 0 && item.AtMs > toMs {
			continue
		}
		out = append(out, item)
	}
	return out
}

func (s *screenshotStore) get(id string) (ScreenshotMeta, string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, item := range s.items {
		if item.ID == id {
			return item, s.filePath(item), true
		}
	}
	return ScreenshotMeta{}, "", false
}

func (h *hub) broadcastScreenshot(meta ScreenshotMeta) {
	payload, err := json.Marshal(map[string]any{
		"type":       "screenshot",
		"screenshot": meta,
		"server_at":  time.Now().UnixMilli(),
	})
	if err != nil {
		return
	}
	h.broadcastPresenceToAdmins(payload)
}

func (h *hub) sendScreenshotSnapshot(a *adminConn) {
	now := time.Now()
	start := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	items := h.screenshots.list("", start.UnixMilli(), now.UnixMilli())
	if len(items) == 0 {
		return
	}
	payload, err := json.Marshal(map[string]any{
		"type":       "screenshot_snapshot",
		"screenshots": items,
		"server_at":  now.UnixMilli(),
	})
	if err != nil {
		return
	}
	a.enqueuePresence(payload)
}

func (h *hub) handleScreenshotUpload(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	clientID := r.Header.Get("X-Client-Id")
	screenshotID := r.Header.Get("X-Screenshot-Id")
	if clientID == "" || screenshotID == "" {
		http.Error(w, "missing client or screenshot id", http.StatusBadRequest)
		return
	}

	h.mu.RLock()
	conn, ok := h.clients[clientID]
	h.mu.RUnlock()
	if !ok {
		http.Error(w, "client not connected", http.StatusForbidden)
		return
	}

	atMs, _ := strconv.ParseInt(r.Header.Get("X-At-Ms"), 10, 64)
	monitorIdx, _ := strconv.ParseUint(r.Header.Get("X-Monitor-Index"), 10, 32)
	width, _ := strconv.ParseUint(r.Header.Get("X-Width"), 10, 32)
	height, _ := strconv.ParseUint(r.Header.Get("X-Height"), 10, 32)

	body := http.MaxBytesReader(w, r.Body, screenshotMaxBodyBytes)
	data, err := io.ReadAll(body)
	if err != nil {
		http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
		return
	}
	if len(data) == 0 {
		http.Error(w, "empty body", http.StatusBadRequest)
		return
	}

	meta := ScreenshotMeta{
		ID:           screenshotID,
		ClientID:     clientID,
		Hostname:     conn.info.Hostname,
		Username:     conn.info.Username,
		MonitorIndex: uint32(monitorIdx),
		AtMs:         atMs,
		Width:        uint32(width),
		Height:       uint32(height),
	}

	if !h.screenshots.enqueue(meta, data) {
		http.Error(w, "server busy", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "id": screenshotID})
}

func (h *hub) handleAPIScreenshots(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	clientID := r.URL.Query().Get("client_id")
	fromMs, _ := strconv.ParseInt(r.URL.Query().Get("from_ms"), 10, 64)
	toMs, _ := strconv.ParseInt(r.URL.Query().Get("to_ms"), 10, 64)

	list := h.screenshots.list(clientID, fromMs, toMs)
	_ = json.NewEncoder(w).Encode(list)
}

func (h *hub) handleAPIScreenshotFile(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	id := r.URL.Path[len("/api/screenshots/file/"):]
	if id == "" {
		http.NotFound(w, r)
		return
	}
	meta, path, ok := h.screenshots.get(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "image/jpeg")
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	http.ServeFile(w, r, path)
	_ = meta
}
