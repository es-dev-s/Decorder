package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
)

// clientAuth controls whether the server requires a client cert.
//
// Phase 1.2: tls.NoClientCert (certs not yet issued)
// Phase 1.5: tls.RequireAndVerifyClientCert (flip after all agents enrolled)
//
// Set the environment variable DECODER_MTLS_ENABLED=1 to flip to mTLS
// without recompiling.
var clientAuth = func() tls.ClientAuthType {
	if os.Getenv("DECODER_MTLS_ENABLED") == "1" {
		return tls.RequireAndVerifyClientCert
	}
	return tls.NoClientCert
}()

// BuildTLSConfig returns the server TLS configuration.
// CRL checking is wired in by Step 2.4 — the VerifyPeerCertificate hook
// is a no-op stub here until crl.go is present.
// certPath returns the value of an env var, or a default.
func certPath(envKey, defaultVal string) string {
	if v := os.Getenv(envKey); v != "" {
		return v
	}
	return defaultVal
}

func BuildTLSConfig() *tls.Config {
	caPath     := certPath("DECODER_CA_CERT", "certs/intermediate-ca.pem")
	serverCert := certPath("DECODER_SERVER_CERT", "certs/server.pem")
	serverKey  := certPath("DECODER_SERVER_KEY", "certs/server-key.pem")

	caCert, err := os.ReadFile(caPath)
	if err != nil {
		panic(fmt.Sprintf("tls: cannot read CA cert (%s): %v", caPath, err))
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCert) {
		panic(fmt.Sprintf("tls: failed to parse CA cert at %s", caPath))
	}

	tlsCert, err := tls.LoadX509KeyPair(serverCert, serverKey)
	if err != nil {
		panic(fmt.Sprintf("tls: cannot load server cert/key (%s / %s): %v", serverCert, serverKey, err))
	}

	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		ClientAuth:   clientAuth,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS13,
		// TLS 1.3 cipher suites are fixed by the spec; these are honoured on ≤1.2 fallback.
		CipherSuites: []uint16{
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
		CurvePreferences:         []tls.CurveID{tls.X25519, tls.CurveP256},
		PreferServerCipherSuites: true,
		// VerifyPeerCertificate is extended by initCRLStore() in crl.go (Step 2.4).
		// The stub here satisfies the interface before crl.go exists.
		VerifyPeerCertificate: verifyCertNotRevoked,
	}
}

// verifyCertNotRevoked is replaced / augmented by crl.go once CRL support is added.
// Before crl.go exists this is a pass-through.
func verifyCertNotRevoked(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	if crlStoreReady() {
		if len(rawCerts) == 0 {
			return nil
		}
		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return err
		}
		if globalCRLStore.IsRevoked(cert.SerialNumber) {
			return errors.New("client certificate has been revoked")
		}
	}
	return nil
}

// VerifyDeviceIdentity ensures the TLS client cert CN matches the claimed device ID.
// Called at the top of handleClientWS after mTLS is enabled (Step 1.5).
func VerifyDeviceIdentity(r *http.Request, claimedDeviceID string) error {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return errors.New("no client certificate presented")
	}
	expected := "device-" + claimedDeviceID + ".stremo.internal"
	got := r.TLS.PeerCertificates[0].Subject.CommonName
	if got != expected {
		return fmt.Errorf("cert CN %q does not match claimed device %q", got, claimedDeviceID)
	}
	return nil
}

// VerifyAdminIdentity ensures the TLS client cert CN is the admin identity.
func VerifyAdminIdentity(r *http.Request) error {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return errors.New("no admin client certificate presented")
	}
	cn := r.TLS.PeerCertificates[0].Subject.CommonName
	if cn != "admin.stremo.internal" {
		return fmt.Errorf("admin cert CN %q not recognised", cn)
	}
	return nil
}

// PeerCertSerial returns the serial number of the first peer certificate, or nil.
func PeerCertSerial(r *http.Request) *big.Int {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil
	}
	return r.TLS.PeerCertificates[0].SerialNumber
}

// PeerCertCN returns the CN of the first peer certificate, or empty string.
func PeerCertCN(r *http.Request) string {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return ""
	}
	return r.TLS.PeerCertificates[0].Subject.CommonName
}
