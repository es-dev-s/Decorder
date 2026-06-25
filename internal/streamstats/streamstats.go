// Package streamstats aggregates per-client relay metrics from frame headers
// (bytes 0–36 of the client v1 wire format). JPEG payloads are never inspected.
package streamstats

import (
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	"decoder-server/internal/protocol"
)

const (
	clientHeaderLen = 37
	frameVersionPlain = 0x01
	frameVersionEnc   = 0x02
)

// Header fields extracted from a client binary frame (header only).
type Header struct {
	Seq        uint64
	Width      uint32
	Height     uint32
	TimestampUs uint64
	Monitor    uint32
	PayloadBytes int
}

// ParseHeader reads the client v1 header. Returns false for legacy/short frames.
func ParseHeader(data []byte) (Header, bool) {
	if len(data) < clientHeaderLen {
		return Header{}, false
	}
	v := data[0]
	if v != frameVersionPlain && v != frameVersionEnc {
		return Header{}, false
	}
	return Header{
		Seq:         binary.LittleEndian.Uint64(data[1:9]),
		Width:       binary.LittleEndian.Uint32(data[9:13]),
		Height:      binary.LittleEndian.Uint32(data[13:17]),
		TimestampUs: binary.LittleEndian.Uint64(data[17:25]),
		Monitor:     binary.LittleEndian.Uint32(data[25:29]),
		PayloadBytes: len(data) - clientHeaderLen,
	}, true
}

type clientWindow struct {
	mu sync.Mutex

	lastSeq       uint64
	seqInit       bool
	droppedFrames uint64

	frameCount uint64
	byteCount  uint64

	lastWidth   uint32
	lastHeight  uint32
	lastMonitor uint32
	lastTsUs    uint64

	windowStart time.Time
}

func (w *clientWindow) record(hdr Header) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.windowStart.IsZero() {
		w.windowStart = time.Now()
	}

	w.frameCount++
	w.byteCount += uint64(hdr.PayloadBytes)
	w.lastWidth = hdr.Width
	w.lastHeight = hdr.Height
	w.lastMonitor = hdr.Monitor
	w.lastTsUs = hdr.TimestampUs

	if w.seqInit {
		if hdr.Seq > w.lastSeq+1 {
			w.droppedFrames += hdr.Seq - w.lastSeq - 1
		} else if hdr.Seq <= w.lastSeq {
			// out-of-order or replay — ignore for gap counting
		}
	} else {
		w.seqInit = true
	}
	w.lastSeq = hdr.Seq
}

func (w *clientWindow) snapshot(clientID string) (protocol.StreamStatsPayload, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.frameCount == 0 {
		return protocol.StreamStatsPayload{}, false
	}

	elapsed := time.Since(w.windowStart).Seconds()
	if elapsed < 0.05 {
		elapsed = 0.05
	}

	fps := int(float64(w.frameCount) / elapsed + 0.5)
	bps := int64(float64(w.byteCount) / elapsed)

	latencyMs := int64(0)
	if w.lastTsUs > 0 {
		nowUs := uint64(time.Now().UnixMicro())
		if nowUs > w.lastTsUs {
			latencyMs = int64((nowUs - w.lastTsUs) / 1000)
		}
	}

	res := fmt.Sprintf("%dx%d", w.lastWidth, w.lastHeight)
	out := protocol.StreamStatsPayload{
		ClientID:      clientID,
		FPS:           fps,
		Resolution:    res,
		Monitor:       w.lastMonitor,
		DroppedFrames: w.droppedFrames,
		LatencyMs:     latencyMs,
		BytesPerSec:   bps,
	}

	// Reset window counters; keep cumulative droppedFrames and last dimensions.
	w.frameCount = 0
	w.byteCount = 0
	w.windowStart = time.Now()

	return out, true
}

// Registry holds per-client rolling windows.
type Registry struct {
	mu      sync.Mutex
	clients map[string]*clientWindow
}

// NewRegistry creates an empty stats registry.
func NewRegistry() *Registry {
	return &Registry{clients: make(map[string]*clientWindow)}
}

// Record ingests a raw client binary frame (header bytes only are read).
func (r *Registry) Record(clientID string, raw []byte) {
	hdr, ok := ParseHeader(raw)
	if !ok {
		return
	}
	r.mu.Lock()
	w, ok := r.clients[clientID]
	if !ok {
		w = &clientWindow{}
		r.clients[clientID] = w
	}
	r.mu.Unlock()
	w.record(hdr)
}

// Remove drops stats for a disconnected client.
func (r *Registry) Remove(clientID string) {
	r.mu.Lock()
	delete(r.clients, clientID)
	r.mu.Unlock()
}

// Snapshot returns relay stats for clientID and resets the measurement window.
func (r *Registry) Snapshot(clientID string) (protocol.StreamStatsPayload, bool) {
	r.mu.Lock()
	w, ok := r.clients[clientID]
	r.mu.Unlock()
	if !ok {
		return protocol.StreamStatsPayload{}, false
	}
	return w.snapshot(clientID)
}
