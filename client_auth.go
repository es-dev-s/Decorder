package main

import (
	"fmt"

	"github.com/google/uuid"
)

func validateClientUUID(id string) error {
	parsed, err := uuid.Parse(id)
	if err != nil {
		return fmt.Errorf("invalid UUID: %w", err)
	}
	if parsed.Version() != 4 {
		return fmt.Errorf("expected UUID v4, got v%d", parsed.Version())
	}
	return nil
}
