// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package webauth

import (
	"strings"
	"testing"
	"time"
)

func TestTOTPMatchesRFC6238Vector(t *testing.T) {
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	code, err := TOTPCode(secret, time.Unix(59, 0))
	if err != nil {
		t.Fatalf("TOTPCode() error = %v", err)
	}
	if code != "287082" {
		t.Fatalf("code = %s, want 287082", code)
	}
	if !VerifyTOTP(secret, code, time.Unix(59, 0), 0) {
		t.Fatal("expected exact TOTP verification to pass")
	}
}

func TestVerifyTOTPWindow(t *testing.T) {
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	code, err := TOTPCode(secret, time.Unix(59, 0))
	if err != nil {
		t.Fatalf("TOTPCode() error = %v", err)
	}
	if VerifyTOTP(secret, code, time.Unix(59+TOTPPeriodSeconds, 0), 0) {
		t.Fatal("expected exact verification to reject previous window")
	}
	if !VerifyTOTP(secret, code, time.Unix(59+TOTPPeriodSeconds, 0), 1) {
		t.Fatal("expected one-window verification to accept previous code")
	}
}

func TestGenerateTOTPSecretAndProvisioningURI(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret() error = %v", err)
	}
	if len(secret) < 16 {
		t.Fatalf("secret too short: %q", secret)
	}
	uri, err := TOTPProvisioningURI("Custodia", "admin", secret)
	if err != nil {
		t.Fatalf("TOTPProvisioningURI() error = %v", err)
	}
	if !strings.HasPrefix(uri, "otpauth://totp/Custodia:admin?") || !strings.Contains(uri, "issuer=Custodia") {
		t.Fatalf("unexpected provisioning uri: %s", uri)
	}
}

func TestVerifyTOTPRejectsMalformedCode(t *testing.T) {
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	for _, code := range []string{"", "12345", "1234567", "abcdef"} {
		if VerifyTOTP(secret, code, time.Unix(59, 0), 1) {
			t.Fatalf("expected malformed code %q to be rejected", code)
		}
	}
}
