package main

import (
	"encoding/json"
	"time"
)

const shutdownDrainWait = 10 * time.Second

// initiateGracefulShutdown notifies admins, stops background work, and closes connections.
func (h *hub) initiateGracefulShutdown() {
	if !h.shuttingDown.CompareAndSwap(false, true) {
		return
	}
	h.relayReady.Store(false)

	msg, err := json.Marshal(map[string]any{
		"type":              "server_shutdown",
		"reason":            "maintenance",
		"reconnect_after_s": 5,
	})
	if err == nil {
		h.broadcastToAdmins(msg)
	}

	h.listMu.Lock()
	if h.listTimer != nil {
		h.listTimer.Stop()
		h.listTimer = nil
	}
	h.listMu.Unlock()

	close(h.bgDone)

	h.mu.Lock()
	for _, c := range h.clients {
		c.close()
	}
	for _, a := range h.admins {
		a.close()
	}
	h.mu.Unlock()

	deadline := time.Now().Add(shutdownDrainWait)
	for time.Now().Before(deadline) {
		if h.activeConns.Load() <= 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
}
