// Decoder relay server — production hub for 100+ concurrent clients.
//
// Concurrency design
// ──────────────────
// • One read goroutine + one write goroutine per WebSocket — no shared writes.
// • watchIndex: clientID → set of admins — O(watchers) frame routing.
// • Video frames: per-client latest-frame slots on each adminConn.
//     - One copy per frame total (built once, shared as immutable across all watchers).
//     - New frame for a client atomically replaces the old one — no queue buildup.
//     - Write pump drains ALL pending latest frames in one pass, then waits.
//     - Stale frames are never sent; admin always sees the most recent image.
// • Text/control: separate reliable channel (client_list, config, policy, cursor).
//     - Drop-oldest only under genuine queue pressure (independent of video).
// • Debounced client_list: fires 100 ms after the LAST event in each burst.
// • cursor/stream_stats routed only to admins watching that specific client.
// • Graceful shutdown: SIGTERM/SIGINT drains connections before exit.

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

const (
	writeWait        = 10 * time.Second
	pongWait         = 60 * time.Second
	pingPeriod       = (pongWait * 9) / 10
	maxMessageSize   = 10 << 20 // 10 MiB
	textQueueDepth   = 128      // control/stats messages per admin
	listDebounce     = 100 * time.Millisecond
	adminClientIDLen = 36 // UUID string prefix on every binary frame
)

// ─── Shared types ─────────────────────────────────────────────────────────────

type MonitorInfo struct {
	Index        uint32 `json:"index"`
	AdapterIndex uint32 `json:"adapter_index,omitempty"`
	OutputIndex  uint32 `json:"output_index,omitempty"`
	Name         string `json:"name"`
	Width        uint32 `json:"width"`
	Height       uint32 `json:"height"`
	X            int32  `json:"x"`
	Y            int32  `json:"y"`
	IsPrimary    bool   `json:"is_primary"`
}

type ClientInfo struct {
	ID            string        `json:"id"`
	Hostname      string        `json:"hostname"`
	Username      string        `json:"username"`
	OS            string        `json:"os"`
	Width         uint32        `json:"width"`
	Height        uint32        `json:"height"`
	FPS           uint32        `json:"fps"`
	Quality       uint32        `json:"quality"`
	MonitorIndex  uint32        `json:"monitor_index"`
	Monitors      []MonitorInfo `json:"monitors"`
	ConnectedAt   time.Time     `json:"connected_at"`
	SessionLocked *bool         `json:"session_locked,omitempty"`
}

type wsMsg struct {
	mt   int
	data []byte
}

// ─── clientConn ───────────────────────────────────────────────────────────────

type clientConn struct {
	info ClientInfo
	conn *websocket.Conn
	send chan wsMsg // outbound text/control messages from server → client
	done chan struct{}

	pressureMu       sync.Mutex
	pressureRouted   uint64
	pressureDropped  uint64
	lastPressureSent time.Time

	// Phase 2.2: per-session replay guard.
	replayMu sync.Mutex
	replay   *ReplayGuard
}

func newClientConn(info ClientInfo, conn *websocket.Conn) *clientConn {
	c := &clientConn{
		info: info,
		conn: conn,
		send: make(chan wsMsg, 32),
		done: make(chan struct{}),
	}
	go c.writePump()
	return c
}

func (c *clientConn) close() {
	select {
	case <-c.done:
	default:
		close(c.done)
	}
}

func (c *clientConn) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer ticker.Stop()
	defer c.conn.Close()
	for {
		select {
		case <-c.done:
			return
		case msg, ok := <-c.send:
			if !ok {
				return
			}
			_ = c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(msg.mt, msg.data); err != nil {
				return
			}
		case <-ticker.C:
			_ = c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// enqueueText copies payload; drops oldest message if queue is full.
func (c *clientConn) enqueueText(data []byte) {
	payload := append([]byte(nil), data...)
	select {
	case c.send <- wsMsg{mt: websocket.TextMessage, data: payload}:
		return
	default:
	}
	select {
	case <-c.send:
	default:
	}
	select {
	case c.send <- wsMsg{mt: websocket.TextMessage, data: payload}:
	default:
	}
}

// ─── adminConn ────────────────────────────────────────────────────────────────
//
// Two outbound paths — completely independent, no head-of-line blocking:
//
//   textSend  — reliable drop-oldest FIFO for control/stats/presence text messages.
//   latestFrames — per-client latest video frame.  A new frame atomically replaces
//                  the previous one for that client (no queue). framePoke (cap 1)
//                  wakes the write pump whenever new frames are ready.
//
// This means: regardless of how many clients are being watched or how fast they
// stream, control messages are never delayed by video backlog, and the admin always
// sees the most recent frame, never a stale one from seconds ago.

type adminConn struct {
	id         string
	conn       *websocket.Conn
	done       chan struct{}
	watchingMu sync.RWMutex
	watching   map[string]struct{}

	// Reliable outbound channel for text frames (control, stats, presence).
	textSend chan wsMsg

	// Per-client latest video frame. Shared byte slice (immutable after build).
	frameMu      sync.Mutex
	latestFrames map[string][]byte // clientID → pre-built admin frame (uuid+jpeg)
	framePoke    chan struct{}       // capacity 1; wakes write pump
}

func newAdminConn(conn *websocket.Conn) *adminConn {
	a := &adminConn{
		id:           uuid.New().String(),
		conn:         conn,
		done:         make(chan struct{}),
		watching:     make(map[string]struct{}),
		textSend:     make(chan wsMsg, textQueueDepth),
		latestFrames: make(map[string][]byte),
		framePoke:    make(chan struct{}, 1),
	}
	go a.writePump()
	return a
}

func (a *adminConn) close() {
	select {
	case <-a.done:
	default:
		close(a.done)
	}
}

// writePump serialises all writes to the admin WebSocket.
// It handles three independent sources: text messages, video frames, and pings.
func (a *adminConn) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer ticker.Stop()
	defer a.conn.Close()

	for {
		select {
		case <-a.done:
			return

		case msg, ok := <-a.textSend:
			if !ok {
				return
			}
			_ = a.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := a.conn.WriteMessage(msg.mt, msg.data); err != nil {
				return
			}

		case <-a.framePoke:
			// Swap out the entire latestFrames map atomically.
			// Frames that arrive during this loop land in the new map and will
			// trigger a new poke — they are never lost.
			a.frameMu.Lock()
			batch := a.latestFrames
			a.latestFrames = make(map[string][]byte, len(batch))
			a.frameMu.Unlock()

			for _, frame := range batch {
				_ = a.conn.SetWriteDeadline(time.Now().Add(writeWait))
				if err := a.conn.WriteMessage(websocket.BinaryMessage, frame); err != nil {
					return
				}
			}

		case <-ticker.C:
			_ = a.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := a.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

func (a *adminConn) watchedClients() []string {
	a.watchingMu.RLock()
	defer a.watchingMu.RUnlock()
	out := make([]string, 0, len(a.watching))
	for id := range a.watching {
		out = append(out, id)
	}
	return out
}

// enqueueText copies data and sends to the text channel; drops oldest on pressure.
func (a *adminConn) enqueueText(data []byte) {
	payload := append([]byte(nil), data...)
	select {
	case a.textSend <- wsMsg{mt: websocket.TextMessage, data: payload}:
		return
	default:
	}
	select {
	case <-a.textSend:
	default:
	}
	select {
	case a.textSend <- wsMsg{mt: websocket.TextMessage, data: payload}:
	default:
	}
}

// enqueuePresence delivers attendance/screenshot events reliably.
// It tries harder than enqueueText before giving up.
func (a *adminConn) enqueuePresence(data []byte) {
	payload := append([]byte(nil), data...)
	for attempt := 0; attempt < 8; attempt++ {
		select {
		case a.textSend <- wsMsg{mt: websocket.TextMessage, data: payload}:
			return
		default:
			select {
			case <-a.textSend:
			default:
				return
			}
		}
	}
}

// enqueueFrame stores the latest frame for clientID and wakes the write pump.
// data MUST be an immutable byte slice (caller must not modify it afterwards).
// Returns true if a previous pending frame was replaced (i.e. the old frame
// will not be sent — used for backpressure accounting).
func (a *adminConn) enqueueFrame(clientID string, data []byte) (replaced bool) {
	a.frameMu.Lock()
	_, replaced = a.latestFrames[clientID]
	a.latestFrames[clientID] = data
	a.frameMu.Unlock()

	select {
	case a.framePoke <- struct{}{}:
	default:
		// Write pump is already awake; it will drain the new frame on its next pass.
	}
	return replaced
}

// removeClientFrames purges all pending frames for clientID when the client
// disconnects and the admin stops watching it.
func (a *adminConn) removeClientFrames(clientID string) {
	a.frameMu.Lock()
	delete(a.latestFrames, clientID)
	a.frameMu.Unlock()
}

// buildAdminFrame prepends the UUID string to the JPEG payload.
// The resulting slice is immutable and can be shared across multiple adminConns.
func buildAdminFrame(clientID string, data []byte) []byte {
	out := make([]byte, adminClientIDLen+len(data))
	copy(out[:adminClientIDLen], clientID)
	copy(out[adminClientIDLen:], data)
	return out
}

// ─── Hub ──────────────────────────────────────────────────────────────────────

type hub struct {
	mu sync.RWMutex

	clients    map[string]*clientConn
	admins     map[string]*adminConn
	watchIndex map[string]map[string]*adminConn // clientID → adminID → admin

	// Reset-based debounced client_list broadcast.
	listMu      sync.Mutex
	listTimer   *time.Timer
	listVersion uint64

	presence    *presenceStore
	screenshots *screenshotStore
	policy      *policyStore

	activeConns atomic.Int64
	startTime   time.Time
}

func newHub() *hub {
	h := &hub{
		clients:    make(map[string]*clientConn),
		admins:     make(map[string]*adminConn),
		watchIndex: make(map[string]map[string]*adminConn),
		presence:   newPresenceStore(),
		startTime:  time.Now(),
	}
	h.screenshots = newScreenshotStore(h.broadcastScreenshot)
	h.policy = loadPolicyStore()
	return h
}

func (h *hub) registerClient(c *clientConn) {
	h.mu.Lock()
	if old, ok := h.clients[c.info.ID]; ok && old != c {
		old.close()
	}
	h.clients[c.info.ID] = c
	h.mu.Unlock()
	log.Printf("[+] client %-36s  %s@%s  %dx%d@%dfps",
		c.info.ID, c.info.Username, c.info.Hostname,
		c.info.Width, c.info.Height, c.info.FPS)
	h.scheduleClientListBroadcast()
}

func (h *hub) unregisterClient(id string, c *clientConn) {
	h.mu.Lock()
	cur, ok := h.clients[id]
	if !ok || cur != c {
		h.mu.Unlock()
		return
	}
	delete(h.clients, id)
	if watchers, ok := h.watchIndex[id]; ok {
		for adminID, a := range watchers {
			a.watchingMu.Lock()
			delete(a.watching, id)
			a.watchingMu.Unlock()
			// Remove pending frames for this client so no stale data lingers.
			a.removeClientFrames(id)
			delete(watchers, adminID)
		}
		delete(h.watchIndex, id)
	}
	h.mu.Unlock()
	log.Printf("[-] client %s", id)
	h.scheduleClientListBroadcast()
}

func (h *hub) registerAdmin(a *adminConn) {
	h.mu.Lock()
	h.admins[a.id] = a
	list := h.buildClientListJSONLocked()
	h.mu.Unlock()
	log.Printf("[+] admin  %s", a.id)
	a.enqueueText(list)
	h.sendPresenceSnapshot(a)
	h.sendScreenshotSnapshot(a)
	h.sendAgentPolicySnapshot(a)
}

func (h *hub) sendPresenceSnapshot(a *adminConn) {
	now := time.Now()
	start := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	events := h.presence.list("", start.UnixMilli(), now.UnixMilli())
	if len(events) == 0 {
		return
	}
	payload, err := json.Marshal(map[string]any{
		"type":      "presence",
		"events":    events,
		"server_at": now.UnixMilli(),
		"snapshot":  true,
	})
	if err != nil {
		return
	}
	a.enqueuePresence(payload)
}

func (h *hub) unregisterAdmin(id string) {
	h.mu.Lock()
	a, ok := h.admins[id]
	if ok {
		a.watchingMu.Lock()
		for clientID := range a.watching {
			if m, exists := h.watchIndex[clientID]; exists {
				delete(m, id)
				if len(m) == 0 {
					delete(h.watchIndex, clientID)
				}
			}
		}
		a.watching = make(map[string]struct{})
		a.watchingMu.Unlock()
		delete(h.admins, id)
	}
	h.mu.Unlock()
	if ok {
		a.close()
	}
	log.Printf("[-] admin  %s", id)
}

func (h *hub) addAdminWatch(a *adminConn, clientID string) {
	if clientID == "" {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()

	a.watchingMu.Lock()
	a.watching[clientID] = struct{}{}
	a.watchingMu.Unlock()

	if h.watchIndex[clientID] == nil {
		h.watchIndex[clientID] = make(map[string]*adminConn)
	}
	h.watchIndex[clientID][a.id] = a
}

func (h *hub) removeAdminWatch(a *adminConn, clientID string) {
	if clientID == "" {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()

	a.watchingMu.Lock()
	delete(a.watching, clientID)
	a.watchingMu.Unlock()
	a.removeClientFrames(clientID)

	if m, ok := h.watchIndex[clientID]; ok {
		delete(m, a.id)
		if len(m) == 0 {
			delete(h.watchIndex, clientID)
		}
	}
}

func (h *hub) clearAdminWatch(a *adminConn) {
	h.mu.Lock()
	defer h.mu.Unlock()

	a.watchingMu.Lock()
	for clientID := range a.watching {
		if m, ok := h.watchIndex[clientID]; ok {
			delete(m, a.id)
			if len(m) == 0 {
				delete(h.watchIndex, clientID)
			}
		}
		a.removeClientFrames(clientID)
	}
	a.watching = make(map[string]struct{})
	a.watchingMu.Unlock()
}

// routeFrame delivers a JPEG frame from clientID to every watching admin.
//
// One copy total: buildAdminFrame creates the framed payload once.
// The same immutable slice is handed to every admin's enqueueFrame — no
// additional copies. Each admin's write pump reads it and sends it over the wire.
func (h *hub) routeFrame(clientID string, data []byte) {
	h.mu.RLock()
	watchers := h.watchIndex[clientID]
	client := h.clients[clientID]
	if len(watchers) == 0 {
		h.mu.RUnlock()
		return
	}
	targets := make([]*adminConn, 0, len(watchers))
	for _, a := range watchers {
		targets = append(targets, a)
	}
	h.mu.RUnlock()

	// Build once, share across all watchers.
	frame := buildAdminFrame(clientID, data)

	replaced := 0
	sent := 0
	for _, a := range targets {
		if a.enqueueFrame(clientID, frame) {
			replaced++
		} else {
			sent++
		}
	}
	// Signal backpressure to the client when a significant fraction of frames
	// are being replaced before delivery (admin is too slow to consume them).
	if client != nil && (sent+replaced) > 0 {
		client.noteRoutePressure(uint64(sent), uint64(replaced))
	}
}

func (c *clientConn) noteRoutePressure(delivered, dropped uint64) {
	c.pressureMu.Lock()
	c.pressureRouted += delivered
	c.pressureDropped += dropped
	now := time.Now()
	if now.Sub(c.lastPressureSent) < 2*time.Second {
		c.pressureMu.Unlock()
		return
	}
	total := c.pressureRouted + c.pressureDropped
	level := 0.0
	if total > 0 {
		level = float64(c.pressureDropped) / float64(total)
	}
	c.pressureRouted = 0
	c.pressureDropped = 0
	c.lastPressureSent = now
	c.pressureMu.Unlock()

	if level < 0.05 {
		return
	}
	msg, _ := json.Marshal(map[string]any{
		"type":  "backpressure",
		"level": level,
	})
	c.enqueueText(msg)
}

// broadcastToAdmins sends to ALL connected admins (client_list, policy, etc.).
func (h *hub) broadcastToAdmins(data []byte) {
	h.mu.RLock()
	admins := make([]*adminConn, 0, len(h.admins))
	for _, a := range h.admins {
		admins = append(admins, a)
	}
	h.mu.RUnlock()
	for _, a := range admins {
		a.enqueueText(data)
	}
}

// broadcastToWatchers sends only to admins watching clientID (cursor, stats).
// At 100 clients × 30fps this avoids O(admins × clients) unnecessary sends.
func (h *hub) broadcastToWatchers(clientID string, data []byte) {
	h.mu.RLock()
	watchers := h.watchIndex[clientID]
	if len(watchers) == 0 {
		h.mu.RUnlock()
		return
	}
	targets := make([]*adminConn, 0, len(watchers))
	for _, a := range watchers {
		targets = append(targets, a)
	}
	h.mu.RUnlock()
	for _, a := range targets {
		a.enqueueText(data)
	}
}

func (h *hub) broadcastPresenceToAdmins(data []byte) {
	h.mu.RLock()
	admins := make([]*adminConn, 0, len(h.admins))
	for _, a := range h.admins {
		admins = append(admins, a)
	}
	h.mu.RUnlock()
	for _, a := range admins {
		a.enqueuePresence(data)
	}
}

func (h *hub) sendControlToClient(clientID string, msg []byte) {
	h.mu.RLock()
	c, ok := h.clients[clientID]
	h.mu.RUnlock()
	if ok {
		c.enqueueText(msg)
	} else {
		log.Printf("    control: client %s not found", clientID)
	}
}

func (h *hub) updateClientInfo(clientID string, fps, quality, monitorIndex uint32) {
	h.mu.Lock()
	if c, ok := h.clients[clientID]; ok {
		if fps > 0 {
			c.info.FPS = fps
		}
		if quality > 0 {
			c.info.Quality = quality
		}
		if monitorIndex < uint32(len(c.info.Monitors)) {
			c.info.MonitorIndex = monitorIndex
			if mon := c.info.Monitors[monitorIndex]; mon.Width > 0 {
				c.info.Width = mon.Width
				c.info.Height = mon.Height
			}
		}
	}
	h.mu.Unlock()
	h.scheduleClientListBroadcast()
}

func (h *hub) updateClientSessionLocked(clientID string, locked bool) {
	var changed bool
	h.mu.Lock()
	if c, ok := h.clients[clientID]; ok {
		if c.info.SessionLocked == nil || *c.info.SessionLocked != locked {
			v := locked
			c.info.SessionLocked = &v
			changed = true
		}
	}
	h.mu.Unlock()
	if !changed {
		return
	}
	payload, _ := json.Marshal(map[string]any{
		"type":           "session_state",
		"client_id":      clientID,
		"session_locked": locked,
	})
	h.broadcastToAdmins(payload)
	h.scheduleClientListBroadcast()
}

func (h *hub) updateClientStatus(clientID string, monitorIndex, width, height uint32) {
	var cfgMsg []byte
	var watching []*adminConn

	h.mu.Lock()
	if c, ok := h.clients[clientID]; ok {
		c.info.MonitorIndex = monitorIndex
		if width > 0 {
			c.info.Width = width
		}
		if height > 0 {
			c.info.Height = height
		}
		cfgMsg = h.buildConfigMsgLocked(clientID, c)
	}
	if m, ok := h.watchIndex[clientID]; ok {
		watching = make([]*adminConn, 0, len(m))
		for _, a := range m {
			watching = append(watching, a)
		}
	}
	h.mu.Unlock()

	h.scheduleClientListBroadcast()
	for _, a := range watching {
		if cfgMsg != nil {
			a.enqueueText(cfgMsg)
		}
	}
}

func parseMonitorsJSON(raw []any) []MonitorInfo {
	out := make([]MonitorInfo, 0, len(raw))
	for _, item := range raw {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		idxF, _ := m["index"].(float64)
		aiF, _ := m["adapter_index"].(float64)
		oiF, _ := m["output_index"].(float64)
		wF, _ := m["width"].(float64)
		hF, _ := m["height"].(float64)
		xF, _ := m["x"].(float64)
		yF, _ := m["y"].(float64)
		name, _ := m["name"].(string)
		isPrimary, _ := m["is_primary"].(bool)
		out = append(out, MonitorInfo{
			Index:        uint32(idxF),
			AdapterIndex: uint32(aiF),
			OutputIndex:  uint32(oiF),
			Name:         name,
			Width:        uint32(wF),
			Height:       uint32(hF),
			X:            int32(xF),
			Y:            int32(yF),
			IsPrimary:    isPrimary,
		})
	}
	return out
}

func (h *hub) updateClientMonitors(clientID string, monitors []MonitorInfo, monitorIndex uint32) {
	var cfgMsg []byte
	var watching []*adminConn

	h.mu.Lock()
	if c, ok := h.clients[clientID]; ok {
		c.info.Monitors = monitors
		c.info.MonitorIndex = monitorIndex
		if monitorIndex < uint32(len(monitors)) {
			if mon := monitors[monitorIndex]; mon.Width > 0 {
				c.info.Width = mon.Width
				c.info.Height = mon.Height
			}
		}
		cfgMsg = h.buildConfigMsgLocked(clientID, c)
	}
	if m, ok := h.watchIndex[clientID]; ok {
		watching = make([]*adminConn, 0, len(m))
		for _, a := range m {
			watching = append(watching, a)
		}
	}
	h.mu.Unlock()

	log.Printf("    client %s monitors updated → %d display(s)", clientID, len(monitors))
	h.scheduleClientListBroadcast()
	for _, a := range watching {
		if cfgMsg != nil {
			a.enqueueText(cfgMsg)
		}
	}
}

// buildConfigMsgLocked builds a "config" JSON message. Must be called with h.mu held.
func (h *hub) buildConfigMsgLocked(clientID string, c *clientConn) []byte {
	m := map[string]any{
		"type":          "config",
		"client_id":     clientID,
		"width":         c.info.Width,
		"height":        c.info.Height,
		"fps":           c.info.FPS,
		"quality":       c.info.Quality,
		"monitor_index": c.info.MonitorIndex,
		"monitors":      c.info.Monitors,
		"codec":         "mjpeg",
	}
	data, _ := json.Marshal(m)
	return data
}

func (h *hub) buildClientListJSONLocked() []byte {
	list := make([]ClientInfo, 0, len(h.clients))
	for _, c := range h.clients {
		list = append(list, c.info)
	}
	msg := map[string]any{"type": "client_list", "clients": list}
	data, _ := json.Marshal(msg)
	return data
}

// scheduleClientListBroadcast collapses bursts of register/unregister events
// into a single broadcast fired 100 ms after the LAST event.
func (h *hub) scheduleClientListBroadcast() {
	h.listMu.Lock()
	h.listVersion++
	ver := h.listVersion
	if h.listTimer != nil {
		h.listTimer.Stop()
	}
	h.listTimer = time.AfterFunc(listDebounce, func() {
		h.listMu.Lock()
		if h.listVersion != ver {
			h.listMu.Unlock()
			return
		}
		h.listTimer = nil
		h.listMu.Unlock()
		h.broadcastClientListNow()
	})
	h.listMu.Unlock()
}

func (h *hub) broadcastClientListNow() {
	h.mu.RLock()
	msg := h.buildClientListJSONLocked()
	admins := make([]*adminConn, 0, len(h.admins))
	for _, a := range h.admins {
		admins = append(admins, a)
	}
	h.mu.RUnlock()
	for _, a := range admins {
		a.enqueueText(msg)
	}
}

func (h *hub) clientConfigJSON(clientID string) []byte {
	h.mu.RLock()
	defer h.mu.RUnlock()
	c, ok := h.clients[clientID]
	if !ok {
		return nil
	}
	return h.buildConfigMsgLocked(clientID, c)
}

// ─── WebSocket upgrader ──────────────────────────────────────────────────────

// upgrader is split: clients use clientUpgrader (any origin, pre-mTLS).
// Admins use adminUpgrader (strict Tauri origin check).
var clientUpgrader = websocket.Upgrader{
	CheckOrigin:       func(*http.Request) bool { return true },
	ReadBufferSize:    4096,
	WriteBufferSize:   256 * 1024,
	EnableCompression: false,
}

var adminUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		o := r.Header.Get("Origin")
		// Allow Tauri local origins only; reject browser origins.
		return o == "tauri://localhost" || o == "https://tauri.localhost" || o == ""
	},
	ReadBufferSize:    4096,
	WriteBufferSize:   256 * 1024,
	EnableCompression: false,
}

// upgrader retained for non-WS handlers; use clientUpgrader/adminUpgrader for WS.
var upgrader = clientUpgrader

func configureConn(conn *websocket.Conn) {
	conn.SetReadLimit(maxMessageSize)
	_ = conn.SetReadDeadline(time.Now().Add(pongWait))
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(pongWait))
	})
}

// ─── Client handler ──────────────────────────────────────────────────────────

func (h *hub) handleClientWS(w http.ResponseWriter, r *http.Request) {
	// Phase 1.5: when mTLS is enabled, verify the client cert CN matches the
	// device ID sent in the hello message.  The check uses the pre-registered
	// device ID — we defer to post-hello validation inside the loop.
	conn, err := clientUpgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("client upgrade: %v", err)
		return
	}
	configureConn(conn)
	h.activeConns.Add(1)
	defer h.activeConns.Add(-1)

	_ = conn.SetReadDeadline(time.Now().Add(pongWait))
	_, raw, err := conn.ReadMessage()
	if err != nil {
		conn.Close()
		return
	}

	var hello struct {
		ID            string        `json:"id"`
		Hostname      string        `json:"hostname"`
		Username      string        `json:"username"`
		OS            string        `json:"os"`
		Width         uint32        `json:"width"`
		Height        uint32        `json:"height"`
		FPS           uint32        `json:"fps"`
		Quality       uint32        `json:"quality"`
		MonitorIndex  uint32        `json:"monitor_index"`
		Monitors      []MonitorInfo `json:"monitors"`
		SessionLocked *bool         `json:"session_locked"`
	}
	if err := json.Unmarshal(raw, &hello); err != nil {
		log.Printf("invalid client hello: %v", err)
		conn.Close()
		return
	}
	if hello.ID == "" {
		hello.ID = uuid.New().String()
	}

	// mTLS identity check: when enabled, the cert CN must match the claimed ID.
	if clientAuth == tls.RequireAndVerifyClientCert {
		if err := VerifyDeviceIdentity(r, hello.ID); err != nil {
			log.Printf("[auth] device identity mismatch: %v", err)
			Audit(AuditEvent{
				EventType:  "client_connect",
				DeviceID:   hello.ID,
				RemoteAddr: r.RemoteAddr,
				CertCN:     PeerCertCN(r),
				Outcome:    "deny",
				Reason:     err.Error(),
			})
			conn.Close()
			return
		}
	}

	info := ClientInfo{
		ID:            hello.ID,
		Hostname:      hello.Hostname,
		Username:      hello.Username,
		OS:            hello.OS,
		Width:         hello.Width,
		Height:        hello.Height,
		FPS:           hello.FPS,
		Quality:       hello.Quality,
		MonitorIndex:  hello.MonitorIndex,
		Monitors:      hello.Monitors,
		ConnectedAt:   time.Now(),
		SessionLocked: hello.SessionLocked,
	}
	if info.Quality == 0 {
		info.Quality = 85
	}
	if info.FPS == 0 {
		info.FPS = 30
	}

	c := newClientConn(info, conn)
	h.registerClient(c)
	h.pushPolicyToClient(c)
	Audit(AuditEvent{
		EventType:  "client_connect",
		DeviceID:   info.ID,
		RemoteAddr: r.RemoteAddr,
		CertCN:     PeerCertCN(r),
		Outcome:    "allow",
	})
	defer func() {
		c.close()
		h.unregisterClient(info.ID, c)
		Audit(AuditEvent{
			EventType: "client_disconnect",
			DeviceID:  info.ID,
			CertCN:    PeerCertCN(r),
			Outcome:   "allow",
		})
	}()

	for {
		_ = conn.SetReadDeadline(time.Now().Add(pongWait))
		mt, data, err := conn.ReadMessage()
		if err != nil {
			break
		}
		switch mt {
		case websocket.BinaryMessage:
			// Read version byte (byte 0) for replay guard (Phase 2.2).
			// Version 0x01 = plain, 0x02 = AES-GCM encrypted.
			// The server relays the entire message as-is — it never decrypts.
			if err := h.checkReplay(info.ID, data); err != nil {
				log.Printf("[replay] %s: %v — dropping frame", info.ID, err)
				Audit(AuditEvent{
					EventType: "client_replay_detected",
					DeviceID:  info.ID,
					RemoteAddr: r.RemoteAddr,
					CertCN:    PeerCertCN(r),
					Outcome:   "deny",
					Reason:    err.Error(),
				})
				continue
			}
			h.routeFrame(info.ID, data)

		case websocket.TextMessage:
			var msg map[string]any
			if err := json.Unmarshal(data, &msg); err != nil {
				continue
			}
			switch msg["type"] {
			case "status":
				idxF, _ := msg["monitor_index"].(float64)
				wF, _ := msg["width"].(float64)
				hF, _ := msg["height"].(float64)
				h.updateClientStatus(info.ID, uint32(idxF), uint32(wF), uint32(hF))

			case "monitors":
				idxF, _ := msg["monitor_index"].(float64)
				if rawMons, ok := msg["monitors"].([]any); ok {
					mons := parseMonitorsJSON(rawMons)
					h.updateClientMonitors(info.ID, mons, uint32(idxF))
				}

			case "stream_stats", "cursor":
				// Route only to admins watching this client.
				msg["client_id"] = info.ID
				if raw, err := json.Marshal(msg); err == nil {
					h.broadcastToWatchers(info.ID, raw)
				}
				if t, _ := msg["type"].(string); t == "stream_stats" {
					if fpsF, ok := msg["fps_target"].(float64); ok && fpsF > 0 {
						h.updateClientInfo(info.ID, uint32(fpsF), 0, 0)
					}
					if qF, ok := msg["quality"].(float64); ok && qF > 0 {
						h.updateClientInfo(info.ID, 0, uint32(qF), 0)
					}
				}

			case "presence_sync":
				h.handlePresenceSync(info.ID, msg)

			case "session_state":
				locked, _ := msg["session_locked"].(bool)
				h.updateClientSessionLocked(info.ID, locked)
			}
		}
	}
}

// ─── Admin handler ────────────────────────────────────────────────────────────

func (h *hub) handleAdminWS(w http.ResponseWriter, r *http.Request) {
	// Phase 1.5: when mTLS is enabled, verify admin cert identity.
	if clientAuth == tls.RequireAndVerifyClientCert {
		if err := VerifyAdminIdentity(r); err != nil {
			log.Printf("[auth] admin identity check failed: %v", err)
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
	}

	conn, err := adminUpgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("admin upgrade: %v", err)
		return
	}
	configureConn(conn)
	h.activeConns.Add(1)
	defer h.activeConns.Add(-1)

	// Phase 2.3: expect first message {"type":"auth","token":"<paseto>"} within 5 s.
	// If DECODER_PASETO_KEY is set (production), token is mandatory.
	// If not set (local dev), token check is skipped.
	if os.Getenv("DECODER_PASETO_KEY") != "" {
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, authRaw, err := conn.ReadMessage()
		if err != nil {
			conn.Close()
			return
		}
		var authMsg map[string]string
		if err := json.Unmarshal(authRaw, &authMsg); err != nil || authMsg["type"] != "auth" || authMsg["token"] == "" {
			_ = conn.WriteMessage(websocket.CloseMessage,
				websocket.FormatCloseMessage(4001, "auth required"))
			conn.Close()
			Audit(AuditEvent{
				EventType:  "admin_connect_denied",
				RemoteAddr: r.RemoteAddr,
				CertCN:     PeerCertCN(r),
				Outcome:    "deny",
				Reason:     "missing or malformed auth message",
			})
			return
		}
		token, err := VerifyAdminToken(authMsg["token"])
		if err != nil {
			_ = conn.WriteMessage(websocket.CloseMessage,
				websocket.FormatCloseMessage(4001, "token invalid"))
			conn.Close()
			Audit(AuditEvent{
				EventType:  "admin_connect_denied",
				RemoteAddr: r.RemoteAddr,
				CertCN:     PeerCertCN(r),
				Outcome:    "deny",
				Reason:     err.Error(),
			})
			return
		}
		adminID, _ := token.GetString("sub")
		log.Printf("[auth] admin authenticated: %s (cert: %s)", adminID, PeerCertCN(r))
	}

	a := newAdminConn(conn)
	h.registerAdmin(a)
	Audit(AuditEvent{
		EventType:  "admin_connect",
		AdminID:    a.id,
		RemoteAddr: r.RemoteAddr,
		CertCN:     PeerCertCN(r),
		Outcome:    "allow",
	})
	defer func() {
		h.unregisterAdmin(a.id)
		Audit(AuditEvent{
			EventType: "admin_disconnect",
			AdminID:   a.id,
			CertCN:    PeerCertCN(r),
			Outcome:   "allow",
		})
	}()

	for {
		_ = conn.SetReadDeadline(time.Now().Add(pongWait))
		_, raw, err := conn.ReadMessage()
		if err != nil {
			break
		}
		var cmd map[string]any
		if err := json.Unmarshal(raw, &cmd); err != nil {
			continue
		}

		switch cmd["type"] {
		case "watch":
			clientID, _ := cmd["client_id"].(string)
			if clientID != "" {
				h.addAdminWatch(a, clientID)
				log.Printf("    admin %s watching %s", a.id, clientID)
				if cfg := h.clientConfigJSON(clientID); cfg != nil {
					a.enqueueText(cfg)
				}
			}

		case "unwatch":
			if clientID, ok := cmd["client_id"].(string); ok && clientID != "" {
				h.removeAdminWatch(a, clientID)
				log.Printf("    admin %s unwatching %s", a.id, clientID)
			} else {
				h.clearAdminWatch(a)
				log.Printf("    admin %s unwatching all", a.id)
			}

		case "control":
			clientID, _ := cmd["client_id"].(string)
			if clientID == "" {
				break
			}
			fpsF, _ := cmd["fps"].(float64)
			qualityF, _ := cmd["quality"].(float64)
			monitorIndexF, _ := cmd["monitor_index"].(float64)
			maxEdgeF, _ := cmd["max_long_edge"].(float64)
			fps := uint32(fpsF)
			quality := uint32(qualityF)
			monitorIndex := uint32(monitorIndexF)
			maxLongEdge := uint32(maxEdgeF)

			ctrl := map[string]any{"type": "control"}
			if fps > 0 {
				ctrl["fps"] = fps
			}
			if quality > 0 {
				ctrl["quality"] = quality
			}
			if _, ok := cmd["monitor_index"]; ok {
				ctrl["monitor_index"] = monitorIndex
			}
			if maxLongEdge > 0 {
				ctrl["max_long_edge"] = maxLongEdge
			}
			if adaptive, ok := cmd["adaptive"].(bool); ok {
				ctrl["adaptive"] = adaptive
			}
			if preset, ok := cmd["preset"].(string); ok && preset != "" {
				ctrl["preset"] = preset
			}
			if followCursor, ok := cmd["follow_cursor"].(bool); ok {
				ctrl["follow_cursor"] = followCursor
			}
			ctrlBytes, _ := json.Marshal(ctrl)

			log.Printf("    control → client %s  fps=%d quality=%d monitor=%d edge=%d",
				clientID, fps, quality, monitorIndex, maxLongEdge)
			h.sendControlToClient(clientID, ctrlBytes)
			h.updateClientInfo(clientID, fps, quality, monitorIndex)

		case "set_agent_policy":
			h.handleSetAgentPolicy(cmd)
		}
	}
}

// ─── REST ─────────────────────────────────────────────────────────────────────

func (h *hub) handleAPIClients(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	h.mu.RLock()
	list := make([]ClientInfo, 0, len(h.clients))
	for _, c := range h.clients {
		list = append(list, c.info)
	}
	h.mu.RUnlock()
	_ = json.NewEncoder(w).Encode(list)
}

func (h *hub) handleHealth(w http.ResponseWriter, _ *http.Request) {
	h.mu.RLock()
	nClients := len(h.clients)
	nAdmins := len(h.admins)
	h.mu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":       "ok",
		"clients":      nClients,
		"admins":       nAdmins,
		"goroutines":   runtime.NumGoroutine(),
		"active_conns": h.activeConns.Load(),
		"uptime_sec":   int(time.Since(h.startTime).Seconds()),
		"go_version":   runtime.Version(),
	})
}

// ─── main ─────────────────────────────────────────────────────────────────────

const defaultPort = "8090"

func main() {
	portDefault := os.Getenv("DECODER_PORT")
	if portDefault == "" {
		portDefault = defaultPort
	}
	port := flag.String("port", portDefault, "TCP port (env: DECODER_PORT, default 8090)")
	flag.Parse()

	log.Printf("Decoder relay  GOMAXPROCS=%d  Go=%s", runtime.GOMAXPROCS(0), runtime.Version())

	// Start audit log.
	auditPath := os.Getenv("DECODER_AUDIT_LOG")
	if auditPath == "" {
		auditPath = "audit.jsonl"
	}
	initAuditLog(auditPath)

	// Start CRL store (no-op if crl.pem does not exist yet).
	crlPath := certPath("DECODER_CRL_PATH", "certs/crl.pem")
	initCRLStore(crlPath)

	// Initialise PASETO key (panics if DECODER_PASETO_KEY is set but invalid).
	if os.Getenv("DECODER_PASETO_KEY") != "" {
		initPasetoKey()
	} else {
		log.Println("[auth] DECODER_PASETO_KEY not set — token auth disabled (dev mode)")
	}

	h := newHub()

	mux := http.NewServeMux()
	mux.Handle("/ws/client", RateLimitMiddleware(http.HandlerFunc(h.handleClientWS)))
	mux.HandleFunc("/ws/admin", h.handleAdminWS)
	h.registerEnrolRoute(mux)
	mux.HandleFunc("/auth/login", h.handleAuthLogin)
	mux.HandleFunc("/auth/refresh", h.handleAuthRefresh)
	mux.HandleFunc("/api/clients", h.handleAPIClients)
	mux.HandleFunc("/api/presence", h.handleAPIPresence)
	mux.HandleFunc("/api/screenshots/upload", h.handleScreenshotUpload)
	mux.HandleFunc("/api/screenshots/file/", h.handleAPIScreenshotFile)
	mux.HandleFunc("/api/screenshots", h.handleAPIScreenshots)
	mux.HandleFunc("/health", h.handleHealth)

	tlsCfg := BuildTLSConfig()

	srv := &http.Server{
		Addr:              ":" + *port,
		Handler:           SecurityHeaders(mux),
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       0,
		WriteTimeout:      0,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		log.Fatalf("listen %s: %v", srv.Addr, err)
	}

	log.Printf("  Client WS:   wss://0.0.0.0%s/ws/client", srv.Addr)
	log.Printf("  Admin WS:    wss://0.0.0.0%s/ws/admin", srv.Addr)
	log.Printf("  Clients API: https://0.0.0.0%s/api/clients", srv.Addr)
	log.Printf("  Health:      https://0.0.0.0%s/health", srv.Addr)

	done := make(chan struct{})
	go func() {
		quit := make(chan os.Signal, 1)
		signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
		sig := <-quit
		log.Printf("Signal %s — shutting down (15 s drain)", sig)
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("Shutdown: %v", err)
		}
		close(done)
	}()

	if err := srv.ServeTLS(ln, certPath("DECODER_SERVER_CERT", "certs/server.pem"), certPath("DECODER_SERVER_KEY", "certs/server-key.pem")); err != nil && err != http.ErrServerClosed {
		log.Fatalf("serve: %v", err)
	}
	<-done
	log.Println("Server stopped cleanly.")
}
