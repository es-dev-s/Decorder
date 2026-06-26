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
	"strings"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"

	"decoder-server/internal/heartbeat"
	"decoder-server/internal/observability"
	"decoder-server/internal/protocol"
	"decoder-server/internal/registry"
	"decoder-server/internal/streamstats"
)

const (
	writeWait        = 10 * time.Second
	pongWait         = 60 * time.Second
	pingPeriod       = (pongWait * 9) / 10
	maxMessageSize   = 10 << 20 // 10 MiB
	textQueueDepth   = 128      // control/stats messages per admin
	listDebounce     = 50 * time.Millisecond
	adminClientIDLen = 36 // UUID string prefix on every binary frame

	appPingInterval      = 500 * time.Millisecond
	appPingTimeout       = 4 * time.Second
	streamStatsTick      = 500 * time.Millisecond
	maxFrameBurstPerPoke = maxWatchesPerAdmin // drain all pending latest frames per wake

	// Scale limits for 500-client deployments.
	maxClients      = 600 // hard cap; 503 above this
	maxWatchesPerAdmin = 20 // max simultaneous watched clients per admin session

	// Idle clients send stream_stats less frequently to reduce relay chatter.
	// Watched clients keep the 500ms cadence for smooth FPS display.
	idleStatsTick = 5 * time.Second

	// Min spacing between backpressure control messages to a client (adaptive.rs).
	pressureNotifyMinInterval = 200 * time.Millisecond
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
	hb   *heartbeat.Monitor

	connectedAt   time.Time
	framesRelayed atomic.Uint64
	remoteIP      string
	enrolled      bool

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
		hb:   heartbeat.NewMonitor("client=" + info.ID),
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
	ticker := time.NewTicker(heartbeat.PingPeriod())
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
			if c.hb.OnPingSent() {
				return
			}
			_ = c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// sendE2EWatcher tells a client that an admin (with its RSA public key) is now
// watching, so the client can wrap its session key to that admin. Non-blocking.
func (c *clientConn) sendE2EWatcher(adminID, pubkeyB64 string) {
	msg, _ := json.Marshal(map[string]string{
		"type":     "e2e_watcher",
		"admin_id": adminID,
		"pubkey":   pubkeyB64,
	})
	c.enqueueText(msg)
}

// sendE2EUnwatch tells a client an admin stopped watching (drop its wrapped key).
func (c *clientConn) sendE2EUnwatch(adminID string) {
	msg, _ := json.Marshal(map[string]string{
		"type":     "e2e_unwatch",
		"admin_id": adminID,
	})
	c.enqueueText(msg)
}

// routeToAdmin sends a raw text message to a single admin by id (used to relay
// the client's wrapped session key back to the specific watching admin).
func (h *hub) routeToAdmin(adminID string, data []byte) {
	h.mu.RLock()
	a := h.admins[adminID]
	h.mu.RUnlock()
	if a != nil {
		a.enqueueText(data)
	}
}

// sendStreamDemand pushes {"type":"stream_demand","level":"live"|"idle"} to the
// client.  boost=true on live tells the agent to flush an instant frame (admin
// just started watching).  Uses reliable enqueue — must not be dropped.
func (c *clientConn) sendStreamDemand(level string, boost bool) {
	payload := map[string]any{
		"type":  "stream_demand",
		"level": level,
	}
	if boost && level == "live" {
		payload["boost"] = true
	}
	msg, _ := json.Marshal(payload)
	c.enqueueTextReliable(msg)
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

// enqueueTextReliable delivers control that must reach the agent (stream_demand).
// Evicts older queued text before giving up so live mode is not stuck at ~1 fps.
func (c *clientConn) enqueueTextReliable(data []byte) {
	payload := append([]byte(nil), data...)
	for attempt := 0; attempt < 64; attempt++ {
		select {
		case c.send <- wsMsg{mt: websocket.TextMessage, data: payload}:
			return
		default:
			select {
			case <-c.send:
			default:
			}
		}
	}
	select {
	case c.send <- wsMsg{mt: websocket.TextMessage, data: payload}:
	case <-time.After(2 * time.Second):
		log.Printf("[warn] stream_demand not queued for client %s (send channel full)", c.info.ID)
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
	hb         *heartbeat.Monitor
	watchingMu sync.RWMutex
	watching   map[string]struct{}

	// Reliable outbound channel for text frames (control, stats, presence).
	textSend chan wsMsg

	// Priority channel for application-level server_ping — must not queue behind
	// stream_stats / client_list when many agents are connected.
	pingSend chan []byte
	pingPoke chan struct{}

	// Per-client latest video frame. Shared byte slice (immutable after build).
	frameMu            sync.Mutex
	latestFrames       map[string][]byte // clientID → pre-built admin frame (uuid+jpeg)
	displacementStreak map[string]int    // consecutive latest-frame replacements per client
	framePoke          chan struct{}     // capacity 1; wakes write pump

	// Application-level ping (separate from WebSocket protocol ping).
	appPingMu     sync.Mutex
	pendingPingMs int64
	pingDeadline  time.Time
	lastRttMs     int64 // server-measured round-trip (single clock, no skew)

	// End-to-end encryption: this admin's RSA public key (base64 SPKI DER),
	// sent once after connect. Empty until received.
	pubkeyMu sync.RWMutex
	pubkey   string
}

func (a *adminConn) setPubkey(b64 string) {
	a.pubkeyMu.Lock()
	a.pubkey = b64
	a.pubkeyMu.Unlock()
}

func (a *adminConn) getPubkey() string {
	a.pubkeyMu.RLock()
	defer a.pubkeyMu.RUnlock()
	return a.pubkey
}

func newAdminConn(conn *websocket.Conn) *adminConn {
	id := uuid.New().String()
	a := &adminConn{
		id:           id,
		conn:         conn,
		done:         make(chan struct{}),
		hb:           heartbeat.NewMonitor("admin=" + id),
		watching:     make(map[string]struct{}),
		textSend:           make(chan wsMsg, textQueueDepth),
		latestFrames:       make(map[string][]byte),
		displacementStreak: make(map[string]int),
		framePoke:          make(chan struct{}, 1),
		pingSend:     make(chan []byte, 1),
		pingPoke:     make(chan struct{}, 1),
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

func (a *adminConn) prepareServerPing() []byte {
	ts := protocol.NowMs()
	a.appPingMu.Lock()
	a.pendingPingMs = ts
	a.pingDeadline = time.Now().Add(appPingTimeout)
	rtt := a.lastRttMs
	a.appPingMu.Unlock()
	// Include the last server-measured RTT so the admin shows true round-trip
	// latency instead of (admin_clock - server_clock), which is corrupted by
	// any clock skew between the operator's PC and the cloud server.
	raw, err := json.Marshal(map[string]any{
		"type":   string(protocol.MsgServerPing),
		"ts":     ts,
		"rtt_ms": rtt,
	})
	if err != nil {
		return nil
	}
	return raw
}

func (a *adminConn) handleAdminPing(ts int64) {
	a.appPingMu.Lock()
	if a.pendingPingMs != 0 && ts == a.pendingPingMs {
		a.pendingPingMs = 0
		// Both timestamps are the server clock → true RTT, skew-free.
		if rtt := protocol.NowMs() - ts; rtt >= 0 {
			a.lastRttMs = rtt
		}
	}
	a.appPingMu.Unlock()
}

func (a *adminConn) appPingExpired() bool {
	a.appPingMu.Lock()
	defer a.appPingMu.Unlock()
	if a.pendingPingMs == 0 {
		return false
	}
	return time.Now().After(a.pingDeadline)
}

// writePump serialises all writes to the admin WebSocket.
// It handles three independent sources: text messages, video frames, and pings.
func (a *adminConn) writePump() {
	ticker := time.NewTicker(heartbeat.PingPeriod())
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

		case <-a.pingPoke:
			for {
				var data []byte
				select {
				case data = <-a.pingSend:
				default:
					data = nil
				}
				if data == nil {
					break
				}
				_ = a.conn.SetWriteDeadline(time.Now().Add(writeWait))
				if err := a.conn.WriteMessage(websocket.TextMessage, data); err != nil {
					return
				}
			}

		case <-a.framePoke:
			// Drain every latest frame (at most maxWatchesPerAdmin entries). Each slot
			// is already latest-only per client — send them all so multi-watch admins
			// don't fall seconds behind while the write pump yields to text/ping.
			for burst := 0; burst < maxFrameBurstPerPoke; burst++ {
				a.frameMu.Lock()
				if len(a.latestFrames) == 0 {
					a.frameMu.Unlock()
					break
				}
				var frame []byte
				var sentClientID string
				for cid, f := range a.latestFrames {
					frame = f
					sentClientID = cid
					delete(a.latestFrames, cid)
					break
				}
				if sentClientID != "" {
					delete(a.displacementStreak, sentClientID)
				}
				more := len(a.latestFrames) > 0
				a.frameMu.Unlock()

				_ = a.conn.SetWriteDeadline(time.Now().Add(writeWait))
				if err := a.conn.WriteMessage(websocket.BinaryMessage, frame); err != nil {
					return
				}
				if !more {
					break
				}
				// Yield to urgent text/ping every 4 frames so heartbeats stay fresh.
				if burst > 0 && burst%4 == 3 {
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
					case <-a.pingPoke:
						for {
							var data []byte
							select {
							case data = <-a.pingSend:
							default:
								data = nil
							}
							if data == nil {
								break
							}
							_ = a.conn.SetWriteDeadline(time.Now().Add(writeWait))
							if err := a.conn.WriteMessage(websocket.TextMessage, data); err != nil {
								return
							}
						}
					default:
					}
				}
			}
			a.frameMu.Lock()
			remaining := len(a.latestFrames) > 0
			a.frameMu.Unlock()
			if remaining {
				select {
				case a.framePoke <- struct{}{}:
				default:
				}
			}

		case <-ticker.C:
			if a.hb.OnPingSent() {
				return
			}
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

// enqueueServerPing delivers server_ping on a priority lane so RTT stays accurate
// even when the text queue is full of stream_stats from hundreds of clients.
func (a *adminConn) enqueueServerPing(data []byte) {
	payload := append([]byte(nil), data...)
	select {
	case a.pingSend <- payload:
	default:
		select {
		case <-a.pingSend:
		default:
		}
		select {
		case a.pingSend <- payload:
		default:
		}
	}
	select {
	case a.pingPoke <- struct{}{}:
	default:
	}
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

// displacementDropWeight maps consecutive slot replacements to a backpressure weight.
func displacementDropWeight(streak int) uint64 {
	switch {
	case streak >= 10:
		return 10
	case streak >= 5:
		return 7
	case streak >= 3:
		return 4
	default:
		return 1
	}
}

// enqueueFrame stores the latest frame for clientID and wakes the write pump.
// data MUST be an immutable byte slice (caller must not modify it afterwards).
// Returns whether a previous pending frame was replaced and the drop weight for
// backpressure accounting (0 when the slot was empty / prior frame was delivered).
func (a *adminConn) enqueueFrame(clientID string, data []byte) (replaced bool, dropWeight uint64) {
	a.frameMu.Lock()
	_, replaced = a.latestFrames[clientID]
	if replaced {
		a.displacementStreak[clientID]++
		dropWeight = displacementDropWeight(a.displacementStreak[clientID])
	} else {
		a.displacementStreak[clientID] = 0
	}
	a.latestFrames[clientID] = data
	a.frameMu.Unlock()

	select {
	case a.framePoke <- struct{}{}:
	default:
		// Write pump is already awake; it will drain the new frame on its next pass.
	}
	return replaced, dropWeight
}

// removeClientFrames purges all pending frames for clientID when the client
// disconnects and the admin stops watching it.
func (a *adminConn) removeClientFrames(clientID string) {
	a.frameMu.Lock()
	delete(a.latestFrames, clientID)
	delete(a.displacementStreak, clientID)
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
	reg        *registry.Registry
	streamStats *streamstats.Registry
	bgDone     chan struct{}

	// Reset-based debounced client_list broadcast.
	listMu      sync.Mutex
	listTimer   *time.Timer
	listVersion uint64

	presence    *presenceStore
	screenshots *screenshotStore
	policy      *policyStore

	activeConns atomic.Int64
	startTime   time.Time

	shuttingDown atomic.Bool
	relayReady   atomic.Bool
	frameSample  atomic.Uint64

	// Latest resource-health JSON per client (clientID → []byte), for instant
	// dashboard display when an admin connects.
	healthCache sync.Map
}

func newHub() *hub {
	h := &hub{
		clients:    make(map[string]*clientConn),
		admins:     make(map[string]*adminConn),
		watchIndex: make(map[string]map[string]*adminConn),
		presence:   newPresenceStore(),
		startTime:  time.Now(),
	}
	h.reg = registry.New(registry.Events{
		OnClientOffline: func(clientID string, ts int64) {
			h.broadcastClientLifecycle("client_offline", clientID, ts, 0)
		},
		OnClientReconnected: func(clientID string, wasOfflineMs int64) {
			h.broadcastClientLifecycle("client_reconnected", clientID, time.Now().UnixMilli(), wasOfflineMs)
		},
	})
	h.screenshots = newScreenshotStore(h.broadcastScreenshot)
	h.policy = loadPolicyStore()
	h.streamStats = streamstats.NewRegistry()
	h.bgDone = make(chan struct{})
	h.relayReady.Store(true)
	h.startBackgroundTasks()
	return h
}

func (h *hub) startBackgroundTasks() {
	go h.streamStatsLoop()
	go h.adminAppPingLoop()
	go h.demandReconcileLoop()
}

func (h *hub) streamStatsLoop() {
	ticker := time.NewTicker(streamStatsTick)
	defer ticker.Stop()
	for {
		select {
		case <-h.bgDone:
			return
		case <-ticker.C:
			h.publishStreamStats()
		}
	}
}

// demandReconcileLoop re-asserts stream_demand every 10s for every connected
// client.  This self-corrects any demand signal that was lost due to a
// dropped message or a race during reconnect.
func (h *hub) demandReconcileLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-h.bgDone:
			return
		case <-ticker.C:
			h.reconcileDemand()
		}
	}
}

func (h *hub) reconcileDemand() {
	type entry struct {
		c     *clientConn
		level string
	}
	h.mu.RLock()
	work := make([]entry, 0, len(h.clients))
	for id, c := range h.clients {
		level := "idle"
		if watchers := h.watchIndex[id]; len(watchers) > 0 {
			level = "live"
		}
		work = append(work, entry{c, level})
	}
	h.mu.RUnlock()

	for _, e := range work {
		e.c.sendStreamDemand(e.level, false)
	}
	h.updateDemandMetrics()
}

func (h *hub) updateDemandMetrics() {
	h.mu.RLock()
	liveStreams := len(h.watchIndex)
	nClients := len(h.clients)
	nAdmins := len(h.admins)
	h.mu.RUnlock()
	observability.SetClientsConnected(int64(nClients))
	observability.SetAdminsConnected(int64(nAdmins))
	observability.SetLiveStreams(int64(liveStreams))
}

func (h *hub) publishStreamStats() {
	h.mu.RLock()
	clientIDs := make([]string, 0, len(h.watchIndex))
	for cid, watchers := range h.watchIndex {
		if len(watchers) > 0 {
			clientIDs = append(clientIDs, cid)
		}
	}
	h.mu.RUnlock()

	for _, clientID := range clientIDs {
		snap, ok := h.streamStats.Snapshot(clientID)
		if !ok {
			continue
		}
		raw, err := protocol.MarshalStreamStatsFlat(snap)
		if err != nil {
			continue
		}
		h.broadcastToWatchers(clientID, raw)
	}
}

func (h *hub) adminAppPingLoop() {
	sendTicker := time.NewTicker(appPingInterval)
	checkTicker := time.NewTicker(1 * time.Second)
	defer sendTicker.Stop()
	defer checkTicker.Stop()

	for {
		select {
		case <-h.bgDone:
			return
		case <-sendTicker.C:
			h.sendAdminServerPings()
		case <-checkTicker.C:
			h.checkAdminAppPingTimeouts()
		}
	}
}

func (h *hub) sendAdminServerPings() {
	h.mu.RLock()
	admins := make([]*adminConn, 0, len(h.admins))
	for _, a := range h.admins {
		admins = append(admins, a)
	}
	h.mu.RUnlock()

	for _, a := range admins {
		if raw := a.prepareServerPing(); len(raw) > 0 {
			a.enqueueServerPing(raw)
		}
	}
}

func (h *hub) checkAdminAppPingTimeouts() {
	h.mu.RLock()
	admins := make([]*adminConn, 0, len(h.admins))
	for _, a := range h.admins {
		admins = append(admins, a)
	}
	h.mu.RUnlock()

	for _, a := range admins {
		if a.appPingExpired() {
			log.Printf("[appping] admin %s application ping timeout — evicting", a.id)
			h.unregisterAdmin(a.id)
		}
	}
}

func (h *hub) broadcastClientLifecycle(msgType, clientID string, ts, wasOfflineMs int64) {
	if h.shuttingDown.Load() {
		return
	}
	payload := map[string]any{
		"type":      msgType,
		"client_id": clientID,
		"ts":        ts,
	}
	if wasOfflineMs > 0 {
		payload["was_offline_ms"] = wasOfflineMs
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return
	}
	h.broadcastToAdmins(raw)
}

func (h *hub) registerClient(c *clientConn) {
	h.mu.Lock()
	if old, ok := h.clients[c.info.ID]; ok && old != c {
		old.close()
	}
	h.clients[c.info.ID] = c
	// Determine initial demand: live if any admin is already watching this client
	// (e.g. admin was watching before agent reconnected).
	initialDemand := "idle"
	type adminKey struct{ id, pubkey string }
	var e2eWatchers []adminKey
	if watchers := h.watchIndex[c.info.ID]; len(watchers) > 0 {
		initialDemand = "live"
		if E2EEnabled() {
			for adminID, a := range watchers {
				if pk := a.getPubkey(); pk != "" {
					e2eWatchers = append(e2eWatchers, adminKey{adminID, pk})
				}
			}
		}
	}
	h.mu.Unlock()

	// Send demand immediately so client knows its streaming mode from the start.
	c.sendStreamDemand(initialDemand, initialDemand == "live")
	// Re-establish E2E key wrapping for any admins already watching.
	for _, w := range e2eWatchers {
		c.sendE2EWatcher(w.id, w.pubkey)
	}

	log.Printf("[+] client %-36s  %s@%s  %dx%d@%dfps  demand=%s",
		c.info.ID, c.info.Username, c.info.Hostname,
		c.info.Width, c.info.Height, c.info.FPS, initialDemand)

	infoJSON, _ := json.Marshal(c.info)
	meta := registry.ClientMeta{InfoJSON: infoJSON}
	if monRaw, err := json.Marshal(c.info.Monitors); err == nil {
		meta.MonitorInfo = monRaw
	}
	h.reg.RegisterClient(c.info.ID, meta)

	h.syncMetricGauges()
	observability.Event("relay", "client_connected",
		"client_id", c.info.ID,
		"ip", c.remoteIP,
		"enrolled", c.enrolled,
	)

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
			a.removeClientFrames(id)
			delete(watchers, adminID)
		}
		delete(h.watchIndex, id)
	}
	info := c.info
	h.mu.Unlock()

	infoJSON, _ := json.Marshal(info)
	meta := registry.ClientMeta{InfoJSON: infoJSON}
	if monRaw, err := json.Marshal(info.Monitors); err == nil {
		meta.MonitorInfo = monRaw
	}
	h.reg.UnregisterClient(id, meta)
	h.streamStats.Remove(id)
	h.healthCache.Delete(id)
	h.syncMetricGauges()

	durationS := int(time.Since(c.connectedAt).Seconds())
	observability.Event("relay", "client_disconnected",
		"client_id", id,
		"duration_s", durationS,
		"frames_relayed", c.framesRelayed.Load(),
	)

	log.Printf("[-] client %s", id)
	h.scheduleClientListBroadcast()
}

func (h *hub) registerAdmin(a *adminConn) {
	h.mu.Lock()
	h.admins[a.id] = a
	list := h.buildClientListJSONLocked()
	h.mu.Unlock()
	h.reg.RegisterAdmin(a.id)
	h.syncMetricGauges()
	observability.Event("relay", "admin_connected", "admin_id", a.id)
	log.Printf("[+] admin  %s", a.id)
	a.enqueueText(list)
	h.sendPresenceSnapshot(a)
	h.sendScreenshotSnapshot(a)
	h.sendAgentPolicySnapshot(a)
	h.sendHealthSnapshot(a)
}

// sendHealthSnapshot pushes the last-known resource health for every client so a
// freshly-connected admin sees CPU/GPU/RAM immediately instead of waiting ~3s.
func (h *hub) sendHealthSnapshot(a *adminConn) {
	h.healthCache.Range(func(_, v any) bool {
		if raw, ok := v.([]byte); ok {
			a.enqueueText(raw)
		}
		return true
	})
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
	nowIdle := make([]*clientConn, 0)
	e2eDrop := make([]*clientConn, 0)
	e2eOn := E2EEnabled()
	if ok {
		a.watchingMu.Lock()
		for clientID := range a.watching {
			if e2eOn {
				if c := h.clients[clientID]; c != nil {
					e2eDrop = append(e2eDrop, c)
				}
			}
			if m, exists := h.watchIndex[clientID]; exists {
				delete(m, id)
				if len(m) == 0 {
					delete(h.watchIndex, clientID)
					if c := h.clients[clientID]; c != nil {
						nowIdle = append(nowIdle, c)
					}
				}
			}
		}
		a.watching = make(map[string]struct{})
		a.watchingMu.Unlock()
		delete(h.admins, id)
	}
	h.mu.Unlock()
	h.reg.UnregisterAdmin(id)
	h.syncMetricGauges()
	if ok {
		a.close()
	}
	log.Printf("[-] admin  %s", id)

	for _, c := range nowIdle {
		c.sendStreamDemand("idle", false)
	}
	for _, c := range e2eDrop {
		c.sendE2EUnwatch(id)
	}
}

func (h *hub) addAdminWatch(a *adminConn, clientID string) {
	if clientID == "" {
		return
	}
	h.mu.Lock()

	a.watchingMu.Lock()
	if len(a.watching) >= maxWatchesPerAdmin {
		a.watchingMu.Unlock()
		h.mu.Unlock()
		log.Printf("[watch] admin %s hit max-watches cap (%d), ignoring watch for %s",
			a.id, maxWatchesPerAdmin, clientID)
		return
	}
	a.watching[clientID] = struct{}{}
	a.watchingMu.Unlock()

	if h.watchIndex[clientID] == nil {
		h.watchIndex[clientID] = make(map[string]*adminConn)
	}
	wasEmpty := len(h.watchIndex[clientID]) == 0
	h.watchIndex[clientID][a.id] = a
	h.reg.AddWatch(a.id, clientID)

	// Collect the client pointer while still under the lock so we can
	// send the demand signal without holding the lock (I/O outside lock).
	target := h.clients[clientID]
	// For E2E, the client always needs THIS admin's public key (even if other
	// admins were already watching) so it can wrap the session key for it.
	var e2eTarget *clientConn
	if E2EEnabled() {
		e2eTarget = h.clients[clientID]
	}
	adminPubkey := a.getPubkey()
	h.mu.Unlock()

	if target != nil {
		// Re-assert live on every watch (handles reconnect / dropped demand).
		target.sendStreamDemand("live", wasEmpty)
	}
	if e2eTarget != nil && adminPubkey != "" {
		e2eTarget.sendE2EWatcher(a.id, adminPubkey)
	}
}

func (h *hub) removeAdminWatch(a *adminConn, clientID string) {
	if clientID == "" {
		return
	}
	h.mu.Lock()

	a.watchingMu.Lock()
	delete(a.watching, clientID)
	a.watchingMu.Unlock()
	a.removeClientFrames(clientID)

	var target *clientConn
	if m, ok := h.watchIndex[clientID]; ok {
		delete(m, a.id)
		if len(m) == 0 {
			delete(h.watchIndex, clientID)
			target = h.clients[clientID]
		}
	}
	h.reg.RemoveWatch(a.id, clientID)
	// E2E: tell the client to drop this admin's wrapped key (whether or not it
	// was the last watcher).
	var e2eTarget *clientConn
	if E2EEnabled() {
		e2eTarget = h.clients[clientID]
	}
	h.mu.Unlock()

	if target != nil {
		target.sendStreamDemand("idle", false)
	}
	if e2eTarget != nil {
		e2eTarget.sendE2EUnwatch(a.id)
	}
}

func (h *hub) clearAdminWatch(a *adminConn) {
	h.mu.Lock()

	// Collect client pointers for demand notifications before modifying state.
	nowIdle := make([]*clientConn, 0)
	e2eDrop := make([]*clientConn, 0)
	e2eOn := E2EEnabled()
	a.watchingMu.Lock()
	for clientID := range a.watching {
		if e2eOn {
			if c := h.clients[clientID]; c != nil {
				e2eDrop = append(e2eDrop, c)
			}
		}
		if m, ok := h.watchIndex[clientID]; ok {
			delete(m, a.id)
			if len(m) == 0 {
				delete(h.watchIndex, clientID)
				if c := h.clients[clientID]; c != nil {
					nowIdle = append(nowIdle, c)
				}
			}
		}
		a.removeClientFrames(clientID)
	}
	a.watching = make(map[string]struct{})
	a.watchingMu.Unlock()
	h.reg.ClearWatch(a.id)
	h.mu.Unlock()

	for _, c := range nowIdle {
		c.sendStreamDemand("idle", false)
	}
	for _, c := range e2eDrop {
		c.sendE2EUnwatch(a.id)
	}
}

// routeFrame delivers a JPEG frame from clientID to every watching admin.
//
// One copy total: buildAdminFrame creates the framed payload once.
// The same immutable slice is handed to every admin's enqueueFrame — no
// additional copies. Each admin's write pump reads it and sends it over the wire.
func (h *hub) routeFrame(clientID string, data []byte) {
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

	// Build once, share across all watchers.
	frame := buildAdminFrame(clientID, data)
	observability.IncFramesRelayed(1)
	observability.IncBytesRelayed(uint64(len(data)))
	if h.frameSample.Add(1)%100 == 0 {
		observability.Event("relay", "frame_relayed",
			"client_id", clientID,
			"bytes", len(data),
		)
	}

	var delivered, dropped uint64
	for _, a := range targets {
		repl, dw := a.enqueueFrame(clientID, frame)
		if repl {
			// Latest-only slot churn at 30fps is normal; only signal congestion once
			// frames pile up without being sent (streak ≥ 3 → dropWeight ≥ 4).
			if dw >= 4 && dw > dropped {
				dropped = dw
			}
		} else {
			delivered++
		}
	}

	h.mu.RLock()
	client := h.clients[clientID]
	h.mu.RUnlock()
	if client != nil && (delivered > 0 || dropped > 0) {
		client.noteRoutePressure(delivered, dropped)
	}
}

func (c *clientConn) noteRoutePressure(delivered, dropped uint64) {
	c.pressureMu.Lock()
	c.pressureRouted += delivered
	c.pressureDropped += dropped
	now := time.Now()
	if now.Sub(c.lastPressureSent) < pressureNotifyMinInterval {
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
		c.enqueueTextReliable(msg)
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
	// Sort oldest-connected first; stable tie-break on ID prevents UI flicker.
	sort.SliceStable(list, func(i, j int) bool {
		if !list[i].ConnectedAt.Equal(list[j].ConnectedAt) {
			return list[i].ConnectedAt.Before(list[j].ConnectedAt)
		}
		return list[i].ID < list[j].ID
	})
	msg := map[string]any{"type": "client_list", "clients": list}
	data, _ := json.Marshal(msg)
	return data
}

// scheduleClientListBroadcast collapses bursts of register/unregister events
// into a single broadcast fired 100 ms after the LAST event.
func (h *hub) scheduleClientListBroadcast() {
	if h.shuttingDown.Load() {
		return
	}
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
	if h.shuttingDown.Load() {
		return
	}
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
		if o == "" || o == "null" {
			return true // Rust-side WS client, same-origin, or sandboxed webview
		}
		// Production Tauri app — both WebView2 and WKWebView origins.
		if o == "tauri://localhost" || o == "https://tauri.localhost" {
			return true
		}
		// Tauri dev mode: Vite dev server (localhost or 127.0.0.1, any port).
		// Identity is enforced by mTLS when certs are present; origin
		// is a secondary hint, not the primary auth mechanism.
		for _, prefix := range []string{
			"http://localhost:",
			"https://localhost:",
			"http://127.0.0.1:",
			"https://127.0.0.1:",
			"http://ipc.localhost",
			"https://ipc.localhost",
		} {
			if strings.HasPrefix(o, prefix) {
				return true
			}
		}
		log.Printf("[ws] admin origin rejected: %q", o)
		return false
	},
	ReadBufferSize:    4096,
	WriteBufferSize:   256 * 1024,
	EnableCompression: false,
}

// upgrader retained for non-WS handlers; use clientUpgrader/adminUpgrader for WS.
var upgrader = clientUpgrader

func configureConn(conn *websocket.Conn, hb *heartbeat.Monitor) {
	conn.SetReadLimit(maxMessageSize)
	deadline := heartbeat.ReadDeadline()
	_ = conn.SetReadDeadline(time.Now().Add(deadline))
	conn.SetPongHandler(func(string) error {
		hb.Touch()
		return conn.SetReadDeadline(time.Now().Add(deadline))
	})
}

// ─── Client handler ──────────────────────────────────────────────────────────

func (h *hub) handleClientWS(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("[panic] client ws handler: %v", rec)
		}
	}()
	if h.shuttingDown.Load() {
		http.Error(w, "server shutting down", http.StatusServiceUnavailable)
		return
	}
	// Enforce hard cap to protect relay at 500-client scale.
	if h.activeConns.Load() >= maxClients {
		http.Error(w, "relay at capacity", http.StatusServiceUnavailable)
		return
	}
	ip := clientIP(r)
	if MtlsRequired() {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			log.Printf("[auth] rejected unauthenticated client, mtls_required=true client_ip=%s", ip)
			observability.Event("auth", "auth_rejected", "ip", ip, "reason", "mtls_required")
			http.Error(w, "client certificate required", http.StatusUnauthorized)
			return
		}
	} else {
		authDebug("[auth] mtls_disabled, accepting client by hello UUID client_ip=%s", ip)
	}

	// Phase 1.5: when mTLS is enabled, verify the client cert CN matches the
	// device ID sent in the hello message.  The check uses the pre-registered
	// device ID — we defer to post-hello validation inside the loop.
	conn, err := clientUpgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("client upgrade: %v", err)
		return
	}
	conn.SetReadLimit(maxMessageSize)
	h.activeConns.Add(1)
	defer h.activeConns.Add(-1)

	_ = conn.SetReadDeadline(time.Now().Add(heartbeat.ReadDeadline()))
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
	} else if err := validateClientUUID(hello.ID); err != nil {
		log.Printf("[auth] rejected invalid client_id=%q client_ip=%s: %v", hello.ID, ip, err)
		_ = conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "invalid_client_id"))
		conn.Close()
		return
	}

	if ok, retryAfter := globalUUIDReconnectLimiter.Allow(hello.ID); !ok {
		log.Printf("[auth] rejected rate-limited reconnect client_id=%s client_ip=%s retry_after=%s", hello.ID, ip, retryAfter)
		_ = conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseTryAgainLater, "reconnect_rate_limited"))
		conn.Close()
		return
	}

	h.mu.Lock()
	if old, ok := h.clients[hello.ID]; ok {
		if old.hb.IsAlive(30 * time.Second) {
			h.mu.Unlock()
			log.Printf("[auth] rejected duplicate client_id=%s client_ip=%s reason=still_connected", hello.ID, ip)
			_ = conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(4001, "duplicate_client_id"))
			conn.Close()
			return
		}
		old.close()
		delete(h.clients, hello.ID)
	}
	h.mu.Unlock()

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
	c.connectedAt = time.Now()
	c.remoteIP = ip
	c.enrolled = PeerCertCN(r) != ""
	configureConn(conn, c.hb)
	c.hb.Touch()
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
		_ = conn.SetReadDeadline(time.Now().Add(heartbeat.ReadDeadline()))
		mt, data, err := conn.ReadMessage()
		if err != nil {
			break
		}
		c.hb.Touch()
		h.reg.TouchClient(info.ID)
		switch mt {
		case websocket.BinaryMessage:
			h.streamStats.Record(info.ID, data)
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
			normalized, err := normalizeClientFrame(data)
			if err != nil {
				log.Printf("[frame] %s normalize: %v — dropping", info.ID, err)
				continue
			}
			c.framesRelayed.Add(1)
			h.routeFrame(info.ID, normalized)

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

			case "e2e_session_key":
				// E2E: client wrapped its session key for a specific admin —
				// route only to that admin. The relay cannot read the key.
				adminID, _ := msg["admin_id"].(string)
				if adminID != "" {
					msg["client_id"] = info.ID
					if raw, err := json.Marshal(msg); err == nil {
						h.routeToAdmin(adminID, raw)
					}
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

			case "health":
				// Resource telemetry (CPU/GPU/RAM) — broadcast to ALL admins so the
				// dashboard shows live resource pressure for every device, watched or not.
				msg["client_id"] = info.ID
				if raw, err := json.Marshal(msg); err == nil {
					h.healthCache.Store(info.ID, raw)
					h.broadcastToAdmins(raw)
				}

			case "presence_sync", "presence_batch":
				h.handlePresenceSync(info.ID, msg)

			case "agent_reconnected":
				offlineMs, _ := msg["offline_ms"].(float64)
				attempt, _ := msg["attempt"].(float64)
				log.Printf("[agent] %s reconnected (attempt=%v offline_ms=%v)", info.ID, attempt, offlineMs)
				observability.IncClientReconnects()
				observability.Event("relay", "client_reconnected",
					"client_id", info.ID,
					"offline_ms", int64(offlineMs),
					"attempt", int(attempt),
				)
				if raw, err := json.Marshal(map[string]any{
					"type":       "agent_reconnected",
					"client_id":  info.ID,
					"offline_ms": offlineMs,
					"attempt":    attempt,
				}); err == nil {
					h.broadcastToWatchers(info.ID, raw)
				}

			case "session_state":
				locked, _ := msg["session_locked"].(bool)
				h.updateClientSessionLocked(info.ID, locked)
			}
		}
	}
}

// ─── Admin handler ────────────────────────────────────────────────────────────

func (h *hub) handleAdminWS(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("[panic] admin ws handler: %v", rec)
		}
	}()
	if h.shuttingDown.Load() {
		http.Error(w, "server shutting down", http.StatusServiceUnavailable)
		return
	}
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
	conn.SetReadLimit(maxMessageSize)
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
	configureConn(conn, a.hb)
	a.hb.Touch()
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
		_ = conn.SetReadDeadline(time.Now().Add(heartbeat.ReadDeadline()))
		_, raw, err := conn.ReadMessage()
		if err != nil {
			break
		}
		a.hb.Touch()
		h.reg.TouchAdmin(a.id)
		var cmd map[string]any
		if err := json.Unmarshal(raw, &cmd); err != nil {
			continue
		}

		switch cmd["type"] {
		case string(protocol.MsgAdminPing):
			tsF, _ := cmd["ts"].(float64)
			a.handleAdminPing(int64(tsF))

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

		case "admin_pubkey":
			// E2E: store this admin's RSA public key so clients can wrap their
			// session keys to it. Re-assert e2e_watcher for everything it watches.
			if pk, _ := cmd["pubkey"].(string); pk != "" {
				a.setPubkey(pk)
				if E2EEnabled() {
					for _, clientID := range a.watchedClients() {
						h.mu.RLock()
						c := h.clients[clientID]
						h.mu.RUnlock()
						if c != nil {
							c.sendE2EWatcher(a.id, pk)
						}
					}
				}
			}
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
	sort.SliceStable(list, func(i, j int) bool {
		if !list[i].ConnectedAt.Equal(list[j].ConnectedAt) {
			return list[i].ConnectedAt.Before(list[j].ConnectedAt)
		}
		return list[i].ID < list[j].ID
	})
	h.mu.RUnlock()
	_ = json.NewEncoder(w).Encode(list)
}

func (h *hub) handleHealth(w http.ResponseWriter, _ *http.Request) {
	// Public liveness endpoint (used by the hosting platform health check).
	// Deliberately minimal — no client/admin counts, goroutine counts, or
	// build/version info, to avoid leaking operational details to the internet.
	// Authenticated operators use /api/status and /metrics for detail.
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":     "ok",
		"uptime_sec": int(time.Since(h.startTime).Seconds()),
	})
}

func (h *hub) handleAPIStatus(w http.ResponseWriter, _ *http.Request) {
	h.mu.RLock()
	liveStreams := len(h.watchIndex)
	h.mu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"connected_clients": h.reg.ClientCount(),
		"connected_admins":  h.reg.AdminCount(),
		"grace_clients":     h.reg.GraceCount(),
		"live_streams":      liveStreams,
		"server_uptime_s":   int(h.reg.Uptime().Seconds()),
		"relay_ok":          h.relayReady.Load() && !h.shuttingDown.Load(),
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

	initFrameCrypto()

	h := newHub()

	mux := http.NewServeMux()
	mux.Handle("/ws/client", IPConnRateLimitMiddleware(RateLimitMiddleware(http.HandlerFunc(h.handleClientWS))))
	mux.Handle("/ws/admin", IPConnRateLimitMiddleware(http.HandlerFunc(h.handleAdminWS)))
	h.registerEnrolRoute(mux)
	mux.HandleFunc("/auth/login", h.handleAuthLogin)
	mux.HandleFunc("/auth/refresh", h.handleAuthRefresh)
	mux.HandleFunc("/api/clients", h.handleAPIClients)
	mux.HandleFunc("/api/presence", h.handleAPIPresence)
	mux.HandleFunc("/api/screenshots/upload", h.handleScreenshotUpload)
	mux.HandleFunc("/api/screenshots/file/", h.handleAPIScreenshotFile)
	mux.HandleFunc("/api/screenshots", h.handleAPIScreenshots)
	mux.HandleFunc("/health", h.handleHealth)
	mux.HandleFunc("/healthz", h.handleHealthz)
	mux.HandleFunc("/readyz", h.handleReadyz)
	mux.HandleFunc("/metrics", h.handleMetrics)
	mux.HandleFunc("/api/status", h.handleAPIStatus)

	tlsCfg := BuildTLSConfig()
	useTLS := tlsCfg != nil

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

	// Fail-closed guard: when DECODER_REQUIRE_TLS=1, refuse to start in plain-HTTP
	// mode. This prevents an accidental cert/config mistake from silently serving
	// the relay without Go-native TLS (defense against downgrade on direct hosting).
	if os.Getenv("DECODER_REQUIRE_TLS") == "1" && !useTLS {
		log.Fatalf("DECODER_REQUIRE_TLS=1 but server certs are missing/unreadable — refusing to start in plain HTTP mode")
	}

	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		log.Fatalf("listen %s: %v", srv.Addr, err)
	}

	if useTLS {
		log.Printf("  Mode:        TLS (Go handles TLS — Railway must use TCP passthrough)")
		log.Printf("  Client WS:   wss://0.0.0.0%s/ws/client", srv.Addr)
		log.Printf("  Admin WS:    wss://0.0.0.0%s/ws/admin", srv.Addr)
	} else {
		log.Printf("  Mode:        plain HTTP (Railway/Cloudflare proxy handles TLS)")
		log.Printf("  Client WS:   ws://0.0.0.0%s/ws/client  (proxied as wss://)", srv.Addr)
		log.Printf("  Admin WS:    ws://0.0.0.0%s/ws/admin   (proxied as wss://)", srv.Addr)
		log.Printf("  NOTE: run certs/init-ca.sh to enable Go-native mTLS")
	}
	log.Printf("  Health:      http://0.0.0.0%s/health  (/healthz /readyz /metrics)", srv.Addr)

	done := make(chan struct{})
	go func() {
		quit := make(chan os.Signal, 1)
		signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
		sig := <-quit
		log.Printf("Signal %s — graceful shutdown", sig)
		h.initiateGracefulShutdown()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("Shutdown: %v", err)
		}
		close(done)
	}()

	var serveErr error
	if useTLS {
		serveErr = srv.ServeTLS(ln,
			certPath("DECODER_SERVER_CERT", "certs/server.pem"),
			certPath("DECODER_SERVER_KEY", "certs/server-key.pem"))
	} else {
		serveErr = srv.Serve(ln)
	}
	if serveErr != nil && serveErr != http.ErrServerClosed {
		log.Fatalf("serve: %v", serveErr)
	}
	<-done
	log.Println("Server stopped cleanly.")
}
