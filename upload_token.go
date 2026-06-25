package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"time"
)

// computeUploadToken matches the client's HMAC-SHA256 upload auth scheme.
func computeUploadToken(clientID string, unixMinute int64) string {
	secret := clientID + strconv.FormatInt(unixMinute, 10)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(clientID))
	return hex.EncodeToString(mac.Sum(nil))
}

// validateUploadToken accepts tokens for the current minute ±1.
func validateUploadToken(clientID, token string) bool {
	if clientID == "" || token == "" {
		return false
	}
	nowMin := time.Now().Unix() / 60
	for _, min := range []int64{nowMin - 1, nowMin, nowMin + 1} {
		if hmac.Equal([]byte(computeUploadToken(clientID, min)), []byte(token)) {
			return true
		}
	}
	return false
}
