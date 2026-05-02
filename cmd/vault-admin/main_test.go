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
