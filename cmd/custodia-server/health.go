// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package main

import (
	"context"
	"encoding/json"
	"net/http"

	"custodia/internal/ratelimit"
	"custodia/internal/store"
)

func buildHealthHandler(vaultStore store.Store, limiter ratelimit.Limiter) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /live", func(w http.ResponseWriter, _ *http.Request) {
		writeHealthJSON(w, http.StatusOK, map[string]string{"status": "live"})
	})
	mux.HandleFunc("GET /ready", func(w http.ResponseWriter, r *http.Request) {
		if err := vaultStore.Health(r.Context()); err != nil {
			writeHealthJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "store_unavailable"})
			return
		}
		if checker, ok := limiter.(ratelimit.HealthChecker); ok {
			if err := checker.Health(r.Context()); err != nil {
				writeHealthJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "rate_limiter_unavailable"})
				return
			}
		}
		writeHealthJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	})
	return mux
}

func writeHealthJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func shutdownServer(ctx context.Context, server *http.Server) {
	if server != nil {
		_ = server.Shutdown(ctx)
	}
}
