// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package ratelimit

import (
	"context"
	"testing"
)

func TestMemoryLimiterAllowsWithinLimitAndRejectsOverLimit(t *testing.T) {
	limiter := NewMemoryLimiter()
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		allowed, err := limiter.Allow(ctx, "client:alice", 2)
		if err != nil {
			t.Fatalf("Allow() error = %v", err)
		}
		if !allowed {
			t.Fatalf("Allow() #%d = false, want true", i+1)
		}
	}
	allowed, err := limiter.Allow(ctx, "client:alice", 2)
	if err != nil {
		t.Fatalf("Allow() error = %v", err)
	}
	if allowed {
		t.Fatal("Allow() over limit = true, want false")
	}
}

func TestMemoryLimiterTreatsNonPositiveLimitAsUnlimited(t *testing.T) {
	limiter := NewMemoryLimiter()
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		allowed, err := limiter.Allow(ctx, "client:alice", 0)
		if err != nil {
			t.Fatalf("Allow() error = %v", err)
		}
		if !allowed {
			t.Fatal("Allow() with zero limit = false, want true")
		}
	}
}

func TestMemoryLimiterHealth(t *testing.T) {
	if err := NewMemoryLimiter().Health(context.Background()); err != nil {
		t.Fatalf("Health() error = %v", err)
	}
}
