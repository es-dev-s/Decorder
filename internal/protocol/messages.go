// Package protocol defines JSON message types for the admin↔server WebSocket channel.
// Binary client frame relay is separate and must not use these types.
package protocol

import (
	"encoding/json"
	"time"
)

type MessageType string

const (
	// Server → Admin
	MsgClientOnline      MessageType = "client_online"
	MsgClientOffline     MessageType = "client_offline"
	MsgClientReconnected MessageType = "client_reconnected"
	MsgPresenceUpdate    MessageType = "presence_update"
	MsgStreamStats       MessageType = "stream_stats"
	MsgPolicyAck         MessageType = "policy_ack"
	MsgServerPing        MessageType = "server_ping"

	// Admin → Server
	MsgWatchClient   MessageType = "watch_client"
	MsgUnwatchClient MessageType = "unwatch_client"
	MsgSetPolicy     MessageType = "set_policy"
	MsgAdminPing     MessageType = "admin_ping"
)

// Envelope is the structured wire format for control messages (Phase 1B+).
type Envelope struct {
	Type    MessageType     `json:"type"`
	Payload json.RawMessage `json:"payload,omitempty"`
	Ts      int64           `json:"ts"`
}

// StreamStatsPayload is relay-side stream health derived from frame headers only.
type StreamStatsPayload struct {
	ClientID      string `json:"client_id"`
	FPS           int    `json:"fps"`
	Resolution    string `json:"resolution"`
	Monitor       uint32 `json:"monitor"`
	DroppedFrames uint64 `json:"dropped_frames"`
	LatencyMs     int64  `json:"latency_ms"`
	BytesPerSec   int64  `json:"bytes_per_sec"`
}

// NowMs returns the current unix timestamp in milliseconds.
func NowMs() int64 {
	return time.Now().UnixMilli()
}

// MarshalEnvelope JSON-encodes a typed envelope.
func MarshalEnvelope(msgType MessageType, payload any, ts int64) ([]byte, error) {
	var raw json.RawMessage
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		raw = b
	}
	return json.Marshal(Envelope{Type: msgType, Payload: raw, Ts: ts})
}

// MarshalServerPing returns {"type":"server_ping","ts":...}.
func MarshalServerPing(ts int64) ([]byte, error) {
	return json.Marshal(map[string]any{
		"type": string(MsgServerPing),
		"ts":   ts,
	})
}

// MarshalStreamStatsFlat returns flat JSON compatible with the existing admin UI
// while also including relay-computed fields for Phase 1C.
func MarshalStreamStatsFlat(p StreamStatsPayload) ([]byte, error) {
	kbps := int(p.BytesPerSec * 8 / 1000)
	if kbps < 0 {
		kbps = 0
	}
	return json.Marshal(map[string]any{
		"type":           string(MsgStreamStats),
		"client_id":      p.ClientID,
		"fps":            p.FPS,
		"fps_target":     p.FPS,
		"fps_effective":  float64(p.FPS),
		"resolution":     p.Resolution,
		"monitor":        p.Monitor,
		"monitor_index":  p.Monitor,
		"dropped_frames": p.DroppedFrames,
		"latency_ms":     p.LatencyMs,
		"bytes_per_sec":  p.BytesPerSec,
		"kbps":           kbps,
		"send_ms_avg":    float64(p.LatencyMs),
		"ts":             NowMs(),
	})
}
