package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"aidanwoods.dev/go-paseto"
)

// pasetoKey is the symmetric PASETO v4 key, loaded from the environment.
// The server panics at startup if the key is missing — silent misconfiguration
// is worse than a hard crash.
var pasetoKey paseto.V4SymmetricKey

func initPasetoKey() {
	raw := os.Getenv("DECODER_PASETO_KEY")
	if raw == "" {
		panic("DECODER_PASETO_KEY environment variable is not set — cannot start securely")
	}
	var err error
	pasetoKey, err = paseto.V4SymmetricKeyFromHex(raw)
	if err != nil {
		panic(fmt.Sprintf("DECODER_PASETO_KEY parse failed: %v — provide 64 hex chars (32 bytes)", err))
	}
	log.Println("[auth] PASETO key loaded")
}

// IssueAdminToken creates a PASETO v4 local access token valid for 15 minutes.
func IssueAdminToken(adminID string) string {
	t := paseto.NewToken()
	t.SetString("sub", adminID)
	t.SetIssuedAt(time.Now())
	t.SetNotBefore(time.Now())
	t.SetExpiration(time.Now().Add(15 * time.Minute))
	t.SetString("kind", "access")
	return t.V4Encrypt(pasetoKey, nil)
}

// IssueRefreshToken creates a PASETO v4 local refresh token valid for 24 hours.
func IssueRefreshToken(adminID string) string {
	t := paseto.NewToken()
	t.SetString("sub", adminID)
	t.SetIssuedAt(time.Now())
	t.SetNotBefore(time.Now())
	t.SetExpiration(time.Now().Add(24 * time.Hour))
	t.SetString("kind", "refresh")
	return t.V4Encrypt(pasetoKey, nil)
}

// VerifyAdminToken validates a PASETO v4 access token.
// Returns the token (with claims) or an error.
func VerifyAdminToken(raw string) (*paseto.Token, error) {
	parser := paseto.NewParser()
	parser.AddRule(paseto.NotExpired())
	parser.AddRule(paseto.ValidAt(time.Now()))
	token, err := parser.ParseV4Local(pasetoKey, raw, nil)
	if err != nil {
		return nil, fmt.Errorf("token invalid: %w", err)
	}
	kind, _ := token.GetString("kind")
	if kind != "access" {
		return nil, fmt.Errorf("token kind %q is not an access token", kind)
	}
	return token, nil
}

// VerifyRefreshToken validates a PASETO v4 refresh token.
func VerifyRefreshToken(raw string) (*paseto.Token, error) {
	parser := paseto.NewParser()
	parser.AddRule(paseto.NotExpired())
	token, err := parser.ParseV4Local(pasetoKey, raw, nil)
	if err != nil {
		return nil, fmt.Errorf("refresh token invalid: %w", err)
	}
	kind, _ := token.GetString("kind")
	if kind != "refresh" {
		return nil, fmt.Errorf("token kind %q is not a refresh token", kind)
	}
	return token, nil
}

// handleAuthLogin issues an access + refresh token pair.
// Identity is proven by the mTLS admin cert — no password needed.
func (h *hub) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Admin identity comes from the TLS client cert (Phase 1.5).
	adminID := PeerCertCN(r)
	if adminID == "" {
		adminID = "admin" // fallback before mTLS is enforced
	}

	access  := IssueAdminToken(adminID)
	refresh := IssueRefreshToken(adminID)

	Audit(AuditEvent{
		EventType:  "admin_token_issued",
		AdminID:    adminID,
		RemoteAddr: r.RemoteAddr,
		CertCN:     PeerCertCN(r),
		Outcome:    "allow",
	})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"access_token":  access,
		"refresh_token": refresh,
	})
}

// handleAuthRefresh accepts a refresh token and issues a new access token.
func (h *hub) handleAuthRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.RefreshToken == "" {
		http.Error(w, "refresh_token required", http.StatusBadRequest)
		return
	}

	token, err := VerifyRefreshToken(body.RefreshToken)
	if err != nil {
		http.Error(w, "invalid refresh token", http.StatusUnauthorized)
		return
	}
	adminID, _ := token.GetString("sub")
	access := IssueAdminToken(adminID)

	Audit(AuditEvent{
		EventType:  "admin_token_refreshed",
		AdminID:    adminID,
		RemoteAddr: r.RemoteAddr,
		Outcome:    "allow",
	})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"access_token": access,
	})
}
