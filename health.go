package main

import (
	"net/http"

	"decoder-server/internal/observability"
)

func (h *hub) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (h *hub) handleReadyz(w http.ResponseWriter, _ *http.Request) {
	if h.shuttingDown.Load() || !h.relayReady.Load() {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ready"))
}

func (h *hub) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(observability.PrometheusText()))
}

func (h *hub) syncMetricGauges() {
	h.mu.RLock()
	nClients := len(h.clients)
	nAdmins := len(h.admins)
	h.mu.RUnlock()
	observability.SetClientsConnected(int64(nClients))
	observability.SetAdminsConnected(int64(nAdmins))
}
