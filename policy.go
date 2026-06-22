package main

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sync"
)

type AgentPolicy struct {
	TimeTracking bool  `json:"time_tracking"`
	Screenshots  bool  `json:"screenshots"`
	Rev          int64 `json:"rev"`
}

type policyStore struct {
	mu   sync.RWMutex
	data AgentPolicy
}

func defaultAgentPolicy() AgentPolicy {
	return AgentPolicy{
		TimeTracking: false,
		Screenshots:  false,
		Rev:          1,
	}
}

func policyFilePath() string {
	base := os.Getenv("DECODER_DATA_DIR")
	if base == "" {
		base = "."
	}
	return filepath.Join(base, "agent-policy.json")
}

func loadPolicyStore() *policyStore {
	ps := &policyStore{data: defaultAgentPolicy()}
	path := policyFilePath()
	raw, err := os.ReadFile(path)
	if err != nil {
		_ = ps.persistLocked()
		return ps
	}
	var loaded AgentPolicy
	if err := json.Unmarshal(raw, &loaded); err != nil {
		log.Printf("agent policy: parse error (%v) — using defaults", err)
		return ps
	}
	if loaded.Rev == 0 {
		loaded.Rev = 1
	}
	ps.data = loaded
	return ps
}

func (p *policyStore) persistLocked() error {
	raw, err := json.MarshalIndent(p.data, "", "  ")
	if err != nil {
		return err
	}
	path := policyFilePath()
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0o755)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (p *policyStore) snapshot() AgentPolicy {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.data
}

func (p *policyStore) update(timeTracking, screenshots *bool) (AgentPolicy, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	prev := p.data
	changed := false
	if timeTracking != nil && *timeTracking != p.data.TimeTracking {
		p.data.TimeTracking = *timeTracking
		changed = true
	}
	if screenshots != nil && *screenshots != p.data.Screenshots {
		p.data.Screenshots = *screenshots
		changed = true
	}
	if !changed {
		return prev, false
	}
	p.data.Rev = prev.Rev + 1
	if p.data.Rev <= prev.Rev {
		p.data.Rev = prev.Rev + 1
	}
	if err := p.persistLocked(); err != nil {
		log.Printf("agent policy: persist failed: %v", err)
	}
	return p.data, true
}

func (h *hub) sendAgentPolicySnapshot(a *adminConn) {
	snap := h.policy.snapshot()
	payload, err := json.Marshal(map[string]any{
		"type":           "agent_policy",
		"time_tracking":  snap.TimeTracking,
		"screenshots":    snap.Screenshots,
		"rev":            snap.Rev,
	})
	if err != nil {
		return
	}
	a.enqueueText(payload)
}

func (h *hub) pushPolicyToClient(c *clientConn) {
	snap := h.policy.snapshot()
	payload, err := json.Marshal(map[string]any{
		"type":          "policy",
		"time_tracking": snap.TimeTracking,
		"screenshots":   snap.Screenshots,
	})
	if err != nil {
		return
	}
	c.enqueueText(payload)
}

func (h *hub) broadcastPolicyToClients() {
	snap := h.policy.snapshot()
	payload, err := json.Marshal(map[string]any{
		"type":          "policy",
		"time_tracking": snap.TimeTracking,
		"screenshots":   snap.Screenshots,
	})
	if err != nil {
		return
	}
	h.mu.RLock()
	clients := make([]*clientConn, 0, len(h.clients))
	for _, c := range h.clients {
		clients = append(clients, c)
	}
	h.mu.RUnlock()
	for _, c := range clients {
		c.enqueueText(payload)
	}
}

func (h *hub) broadcastPolicyToAdmins() {
	snap := h.policy.snapshot()
	payload, err := json.Marshal(map[string]any{
		"type":           "agent_policy",
		"time_tracking":  snap.TimeTracking,
		"screenshots":    snap.Screenshots,
		"rev":            snap.Rev,
	})
	if err != nil {
		return
	}
	h.broadcastToAdmins(payload)
}

func (h *hub) handleSetAgentPolicy(cmd map[string]any) {
	var timeTracking *bool
	var screenshots *bool
	if v, ok := cmd["time_tracking"].(bool); ok {
		timeTracking = &v
	}
	if v, ok := cmd["screenshots"].(bool); ok {
		screenshots = &v
	}
	if timeTracking == nil && screenshots == nil {
		return
	}

	_, changed := h.policy.update(timeTracking, screenshots)
	if !changed {
		h.broadcastPolicyToAdmins()
		return
	}

	snap := h.policy.snapshot()
	log.Printf("    agent policy → time_tracking=%v screenshots=%v rev=%d",
		snap.TimeTracking, snap.Screenshots, snap.Rev)

	h.broadcastPolicyToAdmins()
	h.broadcastPolicyToClients()
}
