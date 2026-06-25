package main

import (
	"encoding/json"
	"log"
	"os"
	"sync"
	"time"
)

// AuditEvent is one structured log entry.
type AuditEvent struct {
	Timestamp  time.Time `json:"ts"`
	EventType  string    `json:"event"`
	DeviceID   string    `json:"device_id,omitempty"`
	AdminID    string    `json:"admin_id,omitempty"`
	RemoteAddr string    `json:"remote_addr,omitempty"`
	CertCN     string    `json:"cert_cn,omitempty"`
	Outcome    string    `json:"outcome"`          // "allow" | "deny"
	Reason     string    `json:"reason,omitempty"`
}

// auditMaxBytes is the rotation threshold. When the active log exceeds this, it
// is rotated to "<path>.1" (single generation) so the audit trail cannot grow
// unbounded and exhaust disk on a long-running cloud host.
const auditMaxBytes int64 = 16 << 20 // 16 MiB

var (
	auditMu    sync.Mutex
	auditFile  *os.File
	auditPath  string
	auditBytes int64
)

func initAuditLog(path string) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		log.Printf("[audit] cannot open %s: %v — audit logging disabled", path, err)
		return
	}
	auditMu.Lock()
	auditFile = f
	auditPath = path
	if fi, statErr := f.Stat(); statErr == nil {
		auditBytes = fi.Size()
	}
	auditMu.Unlock()
	log.Printf("[audit] logging to %s (rotate at %d MiB)", path, auditMaxBytes>>20)
}

// rotateAuditLocked rotates the audit log when it exceeds auditMaxBytes.
// Caller must hold auditMu. Best-effort: on any failure the current file is kept.
func rotateAuditLocked() {
	if auditFile == nil || auditPath == "" || auditBytes < auditMaxBytes {
		return
	}
	_ = auditFile.Close()
	// Single-generation rotation: overwrite the previous .1 backup.
	if err := os.Rename(auditPath, auditPath+".1"); err != nil {
		// Reopen the original so logging continues even if rotation failed.
		if f, e := os.OpenFile(auditPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600); e == nil {
			auditFile = f
		}
		return
	}
	f, err := os.OpenFile(auditPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		auditFile = nil
		return
	}
	auditFile = f
	auditBytes = 0
}

// Audit writes one JSON line to the audit log.
// It is safe to call before initAuditLog (events are silently discarded).
func Audit(e AuditEvent) {
	e.Timestamp = time.Now().UTC()
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	auditMu.Lock()
	defer auditMu.Unlock()
	if auditFile == nil {
		return
	}
	rotateAuditLocked()
	if auditFile == nil {
		return
	}
	line := append(b, '\n')
	n, _ := auditFile.Write(line)
	auditBytes += int64(n)
}
