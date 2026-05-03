package id

import (
	"regexp"
	"testing"
)

func TestNewReturnsUUIDv4(t *testing.T) {
	generated := New()
	pattern := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	if !pattern.MatchString(generated) {
		t.Fatalf("New() = %q, want UUIDv4", generated)
	}
}

func TestNewReturnsUniqueIDs(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		generated := New()
		if seen[generated] {
			t.Fatalf("duplicate id generated: %s", generated)
		}
		seen[generated] = true
	}
}
