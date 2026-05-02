package main

import (
	"net/url"
	"testing"
)

func TestVaultAdminPathEscapeProtectsDynamicSegments(t *testing.T) {
	if got := pathEscape("tenant/client"); got != "tenant%2Fclient" {
		t.Fatalf("unexpected escaped path segment: %q", got)
	}
}

func TestAddQueryFilterTrimsValues(t *testing.T) {
	query := url.Values{}
	addQueryFilter(query, "client_id", " client_alice ")
	if got := query.Get("client_id"); got != "client_alice" {
		t.Fatalf("unexpected query value: %q", got)
	}
}

func TestRunClientListRejectsInvalidLimit(t *testing.T) {
	err := runClientList(&cliConfig{}, []string{"--limit", "501"})
	if err == nil {
		t.Fatal("expected invalid limit error")
	}
}

func TestRunAuditExportRejectsInvalidLimit(t *testing.T) {
	err := runAuditExport(&cliConfig{}, []string{"--limit", "0"})
	if err == nil {
		t.Fatal("expected invalid limit error")
	}
}

func TestRunClientListRejectsInvalidActiveFilter(t *testing.T) {
	err := runClientList(&cliConfig{}, []string{"--active", "maybe"})
	if err == nil {
		t.Fatal("expected invalid active filter error")
	}
}

func TestRunSecretVersionsRejectsInvalidLimit(t *testing.T) {
	err := runSecretVersions(&cliConfig{}, []string{"--secret-id", "550e8400-e29b-41d4-a716-446655440000", "--limit", "501"})
	if err == nil {
		t.Fatal("expected invalid limit error")
	}
}

func TestRunAccessListRejectsInvalidLimit(t *testing.T) {
	err := runAccessList(&cliConfig{}, []string{"--secret-id", "550e8400-e29b-41d4-a716-446655440000", "--limit", "0"})
	if err == nil {
		t.Fatal("expected invalid limit error")
	}
}
