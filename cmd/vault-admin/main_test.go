package main

import "testing"

func TestVaultAdminPathEscapeProtectsDynamicSegments(t *testing.T) {
	if got := pathEscape("tenant/client"); got != "tenant%2Fclient" {
		t.Fatalf("unexpected escaped path segment: %q", got)
	}
}
