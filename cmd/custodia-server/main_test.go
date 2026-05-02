package main

import (
	"context"
	"testing"

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
