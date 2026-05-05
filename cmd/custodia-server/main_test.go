// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package main

import (
	"context"
	"testing"

	"custodia/internal/config"
	"custodia/internal/model"
	"custodia/internal/store"
)

func TestBootstrapClientsCreatesMissingAndIgnoresExisting(t *testing.T) {
	ctx := context.Background()
	memoryStore := store.NewMemoryStore()
	if err := memoryStore.CreateClient(ctx, model.Client{ClientID: "admin", MTLSSubject: "admin"}); err != nil {
		t.Fatalf("seed admin: %v", err)
	}

	err := bootstrapClients(ctx, memoryStore, map[string]string{
		"admin":        "admin",
		"client_alice": "client_alice",
	})
	if err != nil {
		t.Fatalf("bootstrap clients: %v", err)
	}

	clients, err := memoryStore.ListClients(ctx)
	if err != nil {
		t.Fatalf("list clients: %v", err)
	}
	if len(clients) != 2 {
		t.Fatalf("expected 2 clients, got %d: %+v", len(clients), clients)
	}
	if _, err := memoryStore.GetActiveClientBySubject(ctx, "client_alice"); err != nil {
		t.Fatalf("expected bootstrapped client to authenticate: %v", err)
	}
}

func TestValidateDedicatedWebListenerRequiresSeparateAddresses(t *testing.T) {
	if err := validateDedicatedWebListener(":8443", ":9443"); err != nil {
		t.Fatalf("expected separate listeners to be valid: %v", err)
	}
	if err := validateDedicatedWebListener(":8443", ""); err == nil {
		t.Fatal("expected empty web listener to fail")
	}
	if err := validateDedicatedWebListener(":8443", " :8443 "); err == nil {
		t.Fatal("expected shared API/Web listener to fail")
	}
}

func TestValidateAdminClientIDsRejectsInvalidIDs(t *testing.T) {
	if err := validateAdminClientIDs(map[string]bool{"admin": true}); err != nil {
		t.Fatalf("expected valid admin id: %v", err)
	}
	if err := validateAdminClientIDs(map[string]bool{"admin bad": true}); err == nil {
		t.Fatal("expected invalid admin id error")
	}
}

func TestBootstrapClientsRejectsInvalidMappings(t *testing.T) {
	err := bootstrapClients(context.Background(), store.NewMemoryStore(), map[string]string{"client bad": "client_bad"})
	if err == nil {
		t.Fatal("expected invalid bootstrap client id error")
	}
	err = bootstrapClients(context.Background(), store.NewMemoryStore(), map[string]string{"client_good": "client\nsubject"})
	if err == nil {
		t.Fatal("expected invalid bootstrap subject error")
	}
}

func TestBuildStoreRejectsUnsupportedBackend(t *testing.T) {
	_, closeStore, err := buildStore(context.Background(), config.Config{StoreBackend: "badger"})
	if closeStore != nil {
		closeStore()
	}
	if err == nil {
		t.Fatal("expected unsupported store backend error")
	}
}

func TestBuildLimiterRejectsUnsupportedBackend(t *testing.T) {
	_, err := buildLimiter(config.Config{RateLimitBackend: "memcached"})
	if err == nil {
		t.Fatal("expected unsupported rate limit backend error")
	}
}

func TestResolvedBackendsReflectImplicitPersistentConfig(t *testing.T) {
	cfg := config.Config{StoreBackend: "memory", DatabaseURL: "postgres://db", RateLimitBackend: "memory", ValkeyURL: "rediss://cache"}
	if got := resolvedStoreBackend(cfg); got != "postgres" {
		t.Fatalf("expected postgres backend, got %q", got)
	}
	if got := resolvedRateLimitBackend(cfg); got != "valkey" {
		t.Fatalf("expected valkey backend, got %q", got)
	}
}
