package main

import "testing"

func TestUploadTokenRoundTrip(t *testing.T) {
	const id = "550e8400-e29b-41d4-a716-446655440000"
	min := int64(2_900_000)
	token := computeUploadToken(id, min)
	if !validateUploadTokenAt(id, token, min) {
		t.Fatal("expected token to validate at same minute")
	}
}

func validateUploadTokenAt(clientID, token string, unixMinute int64) bool {
	for _, min := range []int64{unixMinute - 1, unixMinute, unixMinute + 1} {
		if computeUploadToken(clientID, min) == token {
			return true
		}
	}
	return false
}
