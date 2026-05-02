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
	_, closeStore, err := buildStore(context.Background(), config.Config{StoreBackend: "sqlite"})
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
