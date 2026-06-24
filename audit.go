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

var (
	auditMu  sync.Mutex
	auditFile *os.File
)

func initAuditLog(path string) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		log.Printf("[audit] cannot open %s: %v — audit logging disabled", path, err)
		return
	}
	auditMu.Lock()
	auditFile = f
	auditMu.Unlock()
	log.Printf("[audit] logging to %s", path)
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
	_, _ = auditFile.Write(append(b, '\n'))
}
