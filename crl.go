package main

import (
	"crypto/x509"
	"errors"
	"log"
	"math/big"
	"os"
	"sync"
	"time"
)

// CRLStore holds the parsed CRL and provides thread-safe revocation checks.
type CRLStore struct {
	mu  sync.RWMutex
	crl *x509.RevocationList
}

var globalCRLStore = &CRLStore{}

// crlStoreReady returns true once a CRL has been loaded at least once.
func crlStoreReady() bool {
	globalCRLStore.mu.RLock()
	defer globalCRLStore.mu.RUnlock()
	return globalCRLStore.crl != nil
}

// Refresh loads or reloads the CRL from disk.
func (s *CRLStore) Refresh(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	crl, err := x509.ParseRevocationList(raw)
	if err != nil {
		return errors.New("crl: parse failed: " + err.Error())
	}
	s.mu.Lock()
	s.crl = crl
	s.mu.Unlock()
	return nil
}

// IsRevoked returns true if the given serial number is on the CRL.
func (s *CRLStore) IsRevoked(serial *big.Int) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.crl == nil {
		return false
	}
	for _, r := range s.crl.RevokedCertificateEntries {
		if r.SerialNumber.Cmp(serial) == 0 {
			return true
		}
	}
	return false
}

// initCRLStore loads the CRL at startup and starts a refresh goroutine.
// If the CRL file does not exist yet (pre-CA setup) the store starts empty
// and all certificates pass; an error is logged but the server starts normally.
func initCRLStore(path string) {
	if err := globalCRLStore.Refresh(path); err != nil {
		log.Printf("[crl] initial load failed (%v) — all certs pass until CRL is present", err)
	} else {
		log.Printf("[crl] loaded %s", path)
	}
	go func() {
		t := time.NewTicker(15 * time.Minute)
		defer t.Stop()
		for range t.C {
			if err := globalCRLStore.Refresh(path); err != nil {
				log.Printf("[crl] refresh failed: %v", err)
			} else {
				log.Printf("[crl] refreshed")
			}
		}
	}()
}
