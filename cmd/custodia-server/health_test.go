// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"custodia/internal/model"
	"custodia/internal/ratelimit"
	"custodia/internal/store"
)

func TestDedicatedHealthHandlerChecksDependencies(t *testing.T) {
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(context.Background(), model.Client{ClientID: "client", MTLSSubject: "client"}); err != nil {
		t.Fatalf("create client: %v", err)
	}
	handler := buildHealthHandler(memoryStore, failingLimiterForHealth{})

	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	if res.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d: %s", res.Code, res.Body.String())
	}
	if !strings.Contains(res.Body.String(), "rate_limiter_unavailable") {
		t.Fatalf("expected limiter error, got %s", res.Body.String())
	}
}

func TestDedicatedHealthLiveDoesNotCheckDependencies(t *testing.T) {
	handler := buildHealthHandler(store.NewMemoryStore(), failingLimiterForHealth{})

	req := httptest.NewRequest(http.MethodGet, "/live", nil)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", res.Code, res.Body.String())
	}
}

type failingLimiterForHealth struct{}

func (failingLimiterForHealth) Allow(context.Context, string, int) (bool, error) { return true, nil }
func (failingLimiterForHealth) Health(context.Context) error                     { return errors.New("down") }

var _ ratelimit.HealthChecker = failingLimiterForHealth{}
