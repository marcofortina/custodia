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

func TestRunClientCommandsRejectInvalidClientIDs(t *testing.T) {
	if err := runClientGet(&cliConfig{}, []string{"--client-id", "client bad"}); err == nil {
		t.Fatal("expected invalid client get id error")
	}
	if err := runClientCreate(&cliConfig{}, []string{"--client-id", "client bad", "--mtls-subject", "subject"}); err == nil {
		t.Fatal("expected invalid client create id error")
	}
	if err := runClientRevoke(&cliConfig{}, []string{"--client-id", "client bad"}); err == nil {
		t.Fatal("expected invalid client revoke id error")
	}
}

func TestRunClientCreateRejectsInvalidMTLSSubject(t *testing.T) {
	err := runClientCreate(&cliConfig{}, []string{"--client-id", "client_good", "--mtls-subject", "bad\nsubject"})
	if err == nil {
		t.Fatal("expected invalid mtls subject error")
	}
}

func TestRunClientListRejectsInvalidLimit(t *testing.T) {
	err := runClientList(&cliConfig{}, []string{"--limit", "501"})
	if err == nil {
		t.Fatal("expected invalid limit error")
	}
}

func TestRunClientRevokeRejectsInvalidReason(t *testing.T) {
	err := runClientRevoke(&cliConfig{}, []string{"--client-id", "client_bob", "--reason", "bad\nreason"})
	if err == nil {
		t.Fatal("expected invalid reason error")
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

func TestRunSecretCommandsRejectInvalidIDs(t *testing.T) {
	if err := runSecretVersions(&cliConfig{}, []string{"--secret-id", "not-a-uuid"}); err == nil {
		t.Fatal("expected invalid secret version id error")
	}
	if err := runAccessList(&cliConfig{}, []string{"--secret-id", "not-a-uuid"}); err == nil {
		t.Fatal("expected invalid access list secret id error")
	}
	if err := runAccessGrantRequest(&cliConfig{}, []string{"--secret-id", "not-a-uuid", "--client-id", "client_bob", "--permissions", "read"}); err == nil {
		t.Fatal("expected invalid grant request secret id error")
	}
	if err := runAccessGrantRequest(&cliConfig{}, []string{"--secret-id", "550e8400-e29b-41d4-a716-446655440000", "--client-id", "client bad", "--permissions", "read"}); err == nil {
		t.Fatal("expected invalid grant request client id error")
	}
	if err := runAccessGrantRequest(&cliConfig{}, []string{"--secret-id", "550e8400-e29b-41d4-a716-446655440000", "--client-id", "client_bob", "--permissions", "read", "--version-id", "latest"}); err == nil {
		t.Fatal("expected invalid grant request version id error")
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

func TestRunAccessGrantRequestRejectsInvalidExpiresAt(t *testing.T) {
	err := runAccessGrantRequest(&cliConfig{}, []string{
		"--secret-id", "550e8400-e29b-41d4-a716-446655440000",
		"--client-id", "client_bob",
		"--permissions", "read",
		"--expires-at", "tomorrow",
	})
	if err == nil {
		t.Fatal("expected invalid expires-at error")
	}
}
