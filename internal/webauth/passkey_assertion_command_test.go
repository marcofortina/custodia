// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package webauth

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyPasskeyAssertionWithCommandAcceptsValidResponse(t *testing.T) {
	command := writeAssertionVerifierScript(t, `#!/usr/bin/env sh
cat >/dev/null
printf '{"valid":true}\n'
`)
	err := VerifyPasskeyAssertionWithCommand(context.Background(), command, validAssertionRequest())
	if err != nil {
		t.Fatalf("VerifyPasskeyAssertionWithCommand() error = %v", err)
	}
}

func TestVerifyPasskeyAssertionWithCommandRejectsInvalidResponse(t *testing.T) {
	command := writeAssertionVerifierScript(t, `#!/usr/bin/env sh
cat >/dev/null
printf '{"valid":false,"error":"bad signature"}\n'
`)
	err := VerifyPasskeyAssertionWithCommand(context.Background(), command, validAssertionRequest())
	if !errors.Is(err, ErrPasskeyAssertionVerificationFailed) {
		t.Fatalf("VerifyPasskeyAssertionWithCommand() error = %v, want %v", err, ErrPasskeyAssertionVerificationFailed)
	}
}

func TestVerifyPasskeyAssertionWithCommandRejectsMissingFields(t *testing.T) {
	err := VerifyPasskeyAssertionWithCommand(context.Background(), "/bin/true", PasskeyAssertionVerificationRequest{})
	if !errors.Is(err, ErrPasskeyAssertionVerificationFailed) {
		t.Fatalf("VerifyPasskeyAssertionWithCommand() error = %v, want %v", err, ErrPasskeyAssertionVerificationFailed)
	}
}

func validAssertionRequest() PasskeyAssertionVerificationRequest {
	return PasskeyAssertionVerificationRequest{
		CredentialID:      "credential-1",
		ClientID:          "admin",
		RPID:              "localhost",
		Origin:            "http://localhost",
		Type:              "webauthn.get",
		ClientDataJSON:    "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0",
		AuthenticatorData: "authenticator-data",
		Signature:         "signature",
		CredentialKeyCOSE: "credential-key-cose",
		SignCount:         2,
	}
}

func writeAssertionVerifierScript(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "verify-passkey")
	if err := os.WriteFile(path, []byte(content), 0o700); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return path
}
