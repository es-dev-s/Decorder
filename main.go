// Decoder relay server — production hub for 100+ concurrent clients.
//
// Concurrency design
// ──────────────────
// • One write-pump goroutine per WebSocket (serialises all writes, no races).
// • watchIndex: clientID → set of admins — O(watchers) frame routing, not O(admins).
// • Every forwarded frame is copied before async handoff (ReadMessage buffer reuse).
// • Binary frames use drop-oldest backpressure (live video: keep latest).
// • client_list broadcasts are debounced (100 ms) to avoid storms at scale.
// • Ping/pong keepalive detects dead peers without blocking the read loop.

package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

const (
	writeWait      = 10 * time.Second
	pongWait       = 60 * time.Second
	pingPeriod     = (pongWait * 9) / 10
	maxMessageSize = 10 << 20 // 10 MiB
	sendQueueDepth = 64       // per-connection outbound buffer
	listDebounce   = 100 * time.Millisecond
	// UUID string length prepended to each binary frame sent to admins.
	adminClientIDLen = 36
)

// ─── Shared types ─────────────────────────────────────────────────────────────

type MonitorInfo struct {
	Index         uint32 `json:"index"`
	AdapterIndex  uint32 `json:"adapter_index,omitempty"`
	OutputIndex   uint32 `json:"output_index,omitempty"`
	Name          string `json:"name"`
	Width         uint32 `json:"width"`
	Height        uint32 `json:"height"`
	X             int32  `json:"x"`
	Y             int32  `json:"y"`
	IsPrimary     bool   `json:"is_primary"`
}

type ClientInfo struct {
	ID           string        `json:"id"`
	Hostname     string        `json:"hostname"`
	Username     string        `json:"username"`
	OS           string        `json:"os"`
	Width        uint32        `json:"width"`
	Height       uint32        `json:"height"`
	FPS          uint32        `json:"fps"`
	Quality      uint32        `json:"quality"`
	MonitorIndex uint32        `json:"monitor_index"`
	Monitors     []MonitorInfo `json:"monitors"`
	ConnectedAt  time.Time     `json:"connected_at"`
}

type wsMsg struct {
	mt   int
	data []byte
}

// ─── clientConn ───────────────────────────────────────────────────────────────

type clientConn struct {
	info ClientInfo
	conn *websocket.Conn
	send chan wsMsg
	done chan struct{}

	pressureMu       sync.Mutex
	pressureRouted   uint64
	pressureDropped  uint64
	lastPressureSent time.Time
}

func newClientConn(info ClientInfo, conn *websocket.Conn) *clientConn {
	c := &clientConn{
		info: info,
		conn: conn,
		send: make(chan wsMsg, sendQueueDepth),
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

type adminConn struct {
	id         string
	conn       *websocket.Conn
	send       chan wsMsg
	done       chan struct{}
	watchingMu sync.RWMutex
	watching   map[string]struct{} // client IDs this admin is viewing
}

func newAdminConn(conn *websocket.Conn) *adminConn {
	a := &adminConn{
		id:       uuid.New().String(),
		conn:     conn,
		send:     make(chan wsMsg, sendQueueDepth),
		done:     make(chan struct{}),
		watching: make(map[string]struct{}),
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

func (a *adminConn) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer ticker.Stop()
	defer a.conn.Close()

	for {
		select {
		case <-a.done:
			return
		case msg, ok := <-a.send:
			if !ok {
				return
			}
			_ = a.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := a.conn.WriteMessage(msg.mt, msg.data); err != nil {
				return
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

func buildAdminFrame(clientID string, clientFrame []byte) []byte {
	out := make([]byte, adminClientIDLen+len(clientFrame))
	copy(out[:adminClientIDLen], clientID)
	copy(out[adminClientIDLen:], clientFrame)
	return out
}

func (a *adminConn) enqueueText(data []byte) {
	payload := append([]byte(nil), data...)
	select {
	case a.send <- wsMsg{mt: websocket.TextMessage, data: payload}:
		return
	default:
	}
	select {
	case <-a.send:
	default:
	}
	select {
	case a.send <- wsMsg{mt: websocket.TextMessage, data: payload}:
	default:
	}
}

// enqueuePresence delivers attendance events reliably — drops oldest queued message if needed.
func (a *adminConn) enqueuePresence(data []byte) {
	payload := append([]byte(nil), data...)
	for attempt := 0; attempt < 8; attempt++ {
		select {
		case a.send <- wsMsg{mt: websocket.TextMessage, data: payload}:
			return
		default:
			select {
			case <-a.send:
			default:
				return
			}
		}
	}
}

// tryEnqueueBinary copies data and drops oldest frame if queue is full (live stream).
// Returns true if the frame was queued for delivery.
func (a *adminConn) tryEnqueueBinary(data []byte) bool {
	payload := append([]byte(nil), data...)
	select {
	case a.send <- wsMsg{mt: websocket.BinaryMessage, data: payload}:
		return true
	default:
	}
	select {
	case <-a.send:
	default:
	}
	select {
	case a.send <- wsMsg{mt: websocket.BinaryMessage, data: payload}:
		return true
	default:
		return false
	}
}

// enqueueBinary copies data and drops oldest frame if queue is full (live stream).
// Never blocks — safe to call from the client read loop at high frame rates.
func (a *adminConn) enqueueBinary(data []byte) {
	_ = a.tryEnqueueBinary(data)
}

// ─── Hub ──────────────────────────────────────────────────────────────────────

type hub struct {
	mu sync.RWMutex

	clients map[string]*clientConn
	admins  map[string]*adminConn

	// watchIndex[clientID][adminID] = admin — only admins watching that client
	watchIndex map[string]map[string]*adminConn

	// Debounced client_list broadcast
	listMu    sync.Mutex
	listTimer *time.Timer

	presence *presenceStore

	screenshots *screenshotStore

	policy *policyStore
}

func newHub() *hub {
	h := &hub{
		clients:    make(map[string]*clientConn),
		admins:     make(map[string]*adminConn),
		watchIndex: make(map[string]map[string]*adminConn),
		presence:   newPresenceStore(),
	}
	h.screenshots = newScreenshotStore(h.broadcastScreenshot)
	h.policy = loadPolicyStore()
	return h
}

func (h *hub) registerClient(c *clientConn) {
	h.mu.Lock()
	h.clients[c.info.ID] = c
	h.mu.Unlock()
	log.Printf("[+] client %-36s  %s@%s  %dx%d@%dfps",
		c.info.ID, c.info.Username, c.info.Hostname,
		c.info.Width, c.info.Height, c.info.FPS)
	h.scheduleClientListBroadcast()
}

func (h *hub) unregisterClient(id string) {
	h.mu.Lock()
	delete(h.clients, id)
	// Remove from watch index
	if watchers, ok := h.watchIndex[id]; ok {
		for adminID, a := range watchers {
			a.watchingMu.Lock()
			delete(a.watching, id)
			a.watchingMu.Unlock()
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
		for clientID := range a.watching {
			if m, exists := h.watchIndex[clientID]; exists {
				delete(m, id)
				if len(m) == 0 {
					delete(h.watchIndex, clientID)
				}
			}
		}
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
	}
	a.watching = make(map[string]struct{})
	a.watchingMu.Unlock()
}

// routeFrame forwards a frame to all admins watching clientID.
// CRITICAL: copies data — gorilla ReadMessage reuses the read buffer.
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

	frame := buildAdminFrame(clientID, data)
	delivered := 0
	dropped := 0
	for _, a := range targets {
		if a.tryEnqueueBinary(frame) {
			delivered++
		} else {
			dropped++
		}
	}
	if client != nil && (delivered > 0 || dropped > 0) {
		client.noteRoutePressure(uint64(delivered), uint64(dropped))
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
		cfgMsg, _ = json.Marshal(m)
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
		cfgMsg, _ = json.Marshal(m)
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

func (h *hub) buildClientListJSONLocked() []byte {
	list := make([]ClientInfo, 0, len(h.clients))
	for _, c := range h.clients {
		list = append(list, c.info)
	}
	msg := map[string]any{"type": "client_list", "clients": list}
	data, _ := json.Marshal(msg)
	return data
}

func (h *hub) scheduleClientListBroadcast() {
	h.listMu.Lock()
	defer h.listMu.Unlock()
	if h.listTimer != nil {
		return
	}
	h.listTimer = time.AfterFunc(listDebounce, func() {
		h.listMu.Lock()
		h.listTimer = nil
		h.listMu.Unlock()
		h.broadcastClientListNow()
	})
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

// ─── WebSocket upgrader ─────────────────────────────────────────────────────

var upgrader = websocket.Upgrader{
	CheckOrigin:     func(*http.Request) bool { return true },
	ReadBufferSize:  4096,
	WriteBufferSize: 256 * 1024,
	EnableCompression: false, // compression adds CPU latency for JPEG streams
}

func configureConn(conn *websocket.Conn) {
	conn.SetReadLimit(maxMessageSize)
	_ = conn.SetReadDeadline(time.Now().Add(pongWait))
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(pongWait))
	})
}

// ─── Client handler ───────────────────────────────────────────────────────────

func (h *hub) handleClientWS(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("client upgrade: %v", err)
		return
	}
	configureConn(conn)

	_, raw, err := conn.ReadMessage()
	if err != nil {
		conn.Close()
		return
	}

	var hello struct {
		ID           string        `json:"id"`
		Hostname     string        `json:"hostname"`
		Username     string        `json:"username"`
		OS           string        `json:"os"`
		Width        uint32        `json:"width"`
		Height       uint32        `json:"height"`
		FPS          uint32        `json:"fps"`
		Quality      uint32        `json:"quality"`
		MonitorIndex uint32        `json:"monitor_index"`
		Monitors     []MonitorInfo `json:"monitors"`
	}
	if err := json.Unmarshal(raw, &hello); err != nil {
		log.Printf("invalid client hello: %v", err)
		conn.Close()
		return
	}
	if hello.ID == "" {
		hello.ID = uuid.New().String()
	}

	info := ClientInfo{
		ID:           hello.ID,
		Hostname:     hello.Hostname,
		Username:     hello.Username,
		OS:           hello.OS,
		Width:        hello.Width,
		Height:       hello.Height,
		FPS:          hello.FPS,
		Quality:      hello.Quality,
		MonitorIndex: hello.MonitorIndex,
		Monitors:     hello.Monitors,
		ConnectedAt:  time.Now(),
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
	defer func() {
		c.close()
		h.unregisterClient(info.ID)
	}()

	for {
		_ = conn.SetReadDeadline(time.Now().Add(pongWait))
		mt, data, err := conn.ReadMessage()
		if err != nil {
			break
		}
		switch mt {
		case websocket.BinaryMessage:
			h.routeFrame(info.ID, data)
		case websocket.TextMessage:
			var msg map[string]any
			if err := json.Unmarshal(data, &msg); err != nil {
				continue
			}
			if msg["type"] == "status" {
				idxF, _ := msg["monitor_index"].(float64)
				wF, _ := msg["width"].(float64)
				hF, _ := msg["height"].(float64)
				h.updateClientStatus(info.ID, uint32(idxF), uint32(wF), uint32(hF))
			} else if msg["type"] == "monitors" {
				idxF, _ := msg["monitor_index"].(float64)
				if rawMons, ok := msg["monitors"].([]any); ok {
					mons := parseMonitorsJSON(rawMons)
					h.updateClientMonitors(info.ID, mons, uint32(idxF))
				}
			} else if msg["type"] == "stream_stats" || msg["type"] == "cursor" {
				msg["client_id"] = info.ID
				if raw, err := json.Marshal(msg); err == nil {
					h.broadcastToAdmins(raw)
				}
				if fpsF, ok := msg["fps_target"].(float64); ok && fpsF > 0 {
					h.updateClientInfo(info.ID, uint32(fpsF), 0, 0)
				}
				if qF, ok := msg["quality"].(float64); ok && qF > 0 {
					h.updateClientInfo(info.ID, 0, uint32(qF), 0)
				}
			} else if msg["type"] == "presence_sync" {
				h.handlePresenceSync(info.ID, msg)
			}
		}
	}
}

// ─── Admin handler ────────────────────────────────────────────────────────────

func (h *hub) handleAdminWS(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("admin upgrade: %v", err)
		return
	}
	configureConn(conn)

	a := newAdminConn(conn)
	h.registerAdmin(a)
	defer func() {
		h.unregisterAdmin(a.id)
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
		"status":  "ok",
		"clients": nClients,
		"admins":  nAdmins,
	})
}

// ─── main ─────────────────────────────────────────────────────────────────────

func main() {
	port := flag.String("port", "8080", "TCP port to listen on")
	flag.Parse()

	h := newHub()

	mux := http.NewServeMux()
	mux.HandleFunc("/ws/client", h.handleClientWS)
	mux.HandleFunc("/ws/admin", h.handleAdminWS)
	mux.HandleFunc("/api/clients", h.handleAPIClients)
	mux.HandleFunc("/api/presence", h.handleAPIPresence)
	mux.HandleFunc("/api/screenshots/upload", h.handleScreenshotUpload)
	mux.HandleFunc("/api/screenshots/file/", h.handleAPIScreenshotFile)
	mux.HandleFunc("/api/screenshots", h.handleAPIScreenshots)
	mux.HandleFunc("/health", h.handleHealth)

	srv := &http.Server{
		Addr:              ":" + *port,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       0, // WebSocket connections are long-lived
		WriteTimeout:      0,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	log.Printf("Decoder relay server  listening on %s", srv.Addr)
	log.Printf("  Client stream:  ws://0.0.0.0%s/ws/client", srv.Addr)
	log.Printf("  Admin viewer:   ws://0.0.0.0%s/ws/admin", srv.Addr)
	log.Printf("  Client list:    http://0.0.0.0%s/api/clients", srv.Addr)
	log.Printf("  Presence log:   http://0.0.0.0%s/api/presence", srv.Addr)
	log.Printf("  Screenshots:    http://0.0.0.0%s/api/screenshots", srv.Addr)
	log.Printf("  Health:         http://0.0.0.0%s/health", srv.Addr)
	log.Fatal(srv.ListenAndServe())
}
