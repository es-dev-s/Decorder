package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"sync"
	"time"
)

// enrolRateLimiter prevents a device from spamming the /enrol endpoint.
type enrolRateLimiter struct {
	mu    sync.Mutex
	last  map[string]time.Time
	limit time.Duration
}

var enrolLimiter = &enrolRateLimiter{
	last:  make(map[string]time.Time),
	limit: time.Hour,
}

func (l *enrolRateLimiter) Allow(deviceID string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if t, ok := l.last[deviceID]; ok && time.Since(t) < l.limit {
		return false
	}
	l.last[deviceID] = time.Now()
	return true
}

type enrolRequest struct {
	DeviceID string `json:"device_id"`
	CSR      string `json:"csr"` // PEM-encoded PKCS#10 CSR
}

type enrolResponse struct {
	CertPEM string `json:"cert_pem"`
}

// handleEnrol signs a device CSR and returns a PEM certificate.
// The endpoint requires TLS but NOT a client cert (it is the bootstrap).
// It loads intermediate-ca.pem and intermediate-ca-key.pem from the certs/ directory.
func (h *hub) handleEnrol(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req enrolRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if req.DeviceID == "" || req.CSR == "" {
		http.Error(w, "device_id and csr required", http.StatusBadRequest)
		return
	}

	if !enrolLimiter.Allow(req.DeviceID) {
		http.Error(w, "rate limit: one enrolment per device per hour", http.StatusTooManyRequests)
		return
	}

	certPEM, err := signDeviceCSR(req.DeviceID, req.CSR)
	if err != nil {
		log.Printf("[enrol] sign failed for %s: %v", req.DeviceID, err)
		http.Error(w, "signing failed", http.StatusInternalServerError)
		return
	}

	Audit(AuditEvent{
		EventType: "device_enrolled",
		DeviceID:  req.DeviceID,
		RemoteAddr: r.RemoteAddr,
		Outcome:   "allow",
	})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(enrolResponse{CertPEM: certPEM})
	log.Printf("[enrol] signed cert for device %s", req.DeviceID)
}

// signDeviceCSR signs the incoming PEM CSR with the Intermediate CA.
func signDeviceCSR(deviceID, csrPEM string) (string, error) {
	// Load Intermediate CA cert + key.
	caKeyPEM, err := os.ReadFile("certs/intermediate-ca-key.pem")
	if err != nil {
		return "", fmt.Errorf("read intermediate-ca-key.pem: %w", err)
	}
	caCertPEM, err := os.ReadFile("certs/intermediate-ca.pem")
	if err != nil {
		return "", fmt.Errorf("read intermediate-ca.pem: %w", err)
	}

	tlsCACert, err := tls.X509KeyPair(caCertPEM, caKeyPEM)
	if err != nil {
		return "", fmt.Errorf("parse CA key pair: %w", err)
	}
	caCert, err := x509.ParseCertificate(tlsCACert.Certificate[0])
	if err != nil {
		return "", fmt.Errorf("parse CA cert: %w", err)
	}
	caPrivKey, ok := tlsCACert.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("intermediate CA key is not ECDSA")
	}

	// Parse the incoming CSR.
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		// Accept partial/minimal CSRs from the agent's placeholder implementation.
		// For a production system, enforce full PKCS#10 validation.
		log.Printf("[enrol] CSR parse warning for %s — using placeholder cert", deviceID)
		return generatePlaceholderCert(deviceID, caCert, caPrivKey)
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		log.Printf("[enrol] CSR parse error for %s (%v) — using placeholder", deviceID, err)
		return generatePlaceholderCert(deviceID, caCert, caPrivKey)
	}
	if err := csr.CheckSignature(); err != nil {
		return "", fmt.Errorf("CSR signature invalid: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", fmt.Errorf("serial generation: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:         "device-" + deviceID + ".stremo.internal",
			Organization:       []string{"Decoder"},
			OrganizationalUnit: []string{"Device"},
		},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, csr.PublicKey, caPrivKey)
	if err != nil {
		return "", fmt.Errorf("create certificate: %w", err)
	}

	certPEMOut := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	return string(certPEMOut), nil
}

// generatePlaceholderCert creates a device cert with a freshly generated key
// for the rare case the CSR cannot be parsed.  This is only used during the
// transition to the rcgen-based CSR flow — the returned cert has a new keypair
// that the agent can't use.  In practice, reject instead of generating.
func generatePlaceholderCert(deviceID string, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) (string, error) {
	return "", fmt.Errorf("CSR required — placeholder cert disabled in production; enrol agent must send valid PKCS#10 CSR for device %s", deviceID)
}

// loadEnrolRoute registers the /enrol handler on the mux.
func (h *hub) registerEnrolRoute(mux *http.ServeMux) {
	mux.HandleFunc("/enrol", h.handleEnrol)
}

// Ensure generateECDSAKey is available for other callers.
func generateECDSAKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}
