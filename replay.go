package main

import (
	"encoding/binary"
	"fmt"
	"sync"
)

const (
	replayWindowSize = 64
	frameHeaderLen   = 37 // 1 version + 8 seq + 28 legacy = 37
)

// ReplayGuard maintains a per-session sliding window of accepted sequence numbers.
// It blocks replayed and far-future frames at the application layer, independent
// of the GCM nonce uniqueness check in frame_crypto.
type ReplayGuard struct {
	mu       sync.Mutex
	expected uint64
	window   [replayWindowSize]bool
}

// Check returns nil if seq is acceptable, or an error if it is a replay or
// too far ahead of the expected position.
func (g *ReplayGuard) Check(seq uint64) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if seq < g.expected {
		return fmt.Errorf("replay detected: seq %d < expected %d", seq, g.expected)
	}
	if seq >= g.expected+replayWindowSize {
		return fmt.Errorf("seq %d too far ahead of expected %d", seq, g.expected)
	}

	idx := seq % replayWindowSize
	if g.window[idx] {
		return fmt.Errorf("duplicate seq %d — replay", seq)
	}
	g.window[idx] = true

	// Advance the window while the next expected seq is already seen.
	for g.window[g.expected%replayWindowSize] {
		g.window[g.expected%replayWindowSize] = false
		g.expected++
	}
	return nil
}

// extractSeq reads the 8-byte sequence number from bytes 1-8 of the frame.
// Returns (seq, ok). ok is false if data is too short.
func extractSeq(data []byte) (uint64, bool) {
	if len(data) < frameHeaderLen {
		return 0, false
	}
	return binary.LittleEndian.Uint64(data[1:9]), true
}

// checkReplay is called by the hub on every inbound binary frame.
func (h *hub) checkReplay(clientID string, data []byte) error {
	seq, ok := extractSeq(data)
	if !ok {
		// Frame too short — likely a legacy plain frame without header.
		// Pass it through without replay checking until all agents upgrade.
		return nil
	}

	h.mu.RLock()
	c, exists := h.clients[clientID]
	h.mu.RUnlock()
	if !exists {
		return nil
	}

	c.replayMu.Lock()
	if c.replay == nil {
		c.replay = &ReplayGuard{}
	}
	guard := c.replay
	c.replayMu.Unlock()

	return guard.Check(seq)
}
