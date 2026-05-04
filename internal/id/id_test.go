// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

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
