package main

import "testing"

func TestValidateClientUUID(t *testing.T) {
	if err := validateClientUUID("550e8400-e29b-41d4-a716-446655440000"); err != nil {
		t.Fatalf("valid v4: %v", err)
	}
	if err := validateClientUUID("not-a-uuid"); err == nil {
		t.Fatal("expected error for invalid uuid")
	}
	if err := validateClientUUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8"); err == nil {
		t.Fatal("expected error for non-v4 uuid")
	}
}
