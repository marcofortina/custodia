// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sdk "custodia/pkg/client"
)

func TestKeyGenerateWritesUsableLocalKeyPair(t *testing.T) {
	dir := t.TempDir()
	privatePath := filepath.Join(dir, "client_alice.x25519.json")
	publicPath := filepath.Join(dir, "client_alice.x25519.pub.json")
	var stdout, stderr bytes.Buffer
	code := (&app{stdout: &stdout, stderr: &stderr}).run([]string{"key", "generate", "--client-id", "client_alice", "--private-key-out", privatePath, "--public-key-out", publicPath})
	if code != 0 {
		t.Fatalf("key generate failed with %d: %s", code, stderr.String())
	}
	privatePayload, privateKey, err := readPrivateKeyFile(privatePath)
	if err != nil {
		t.Fatalf("read private key: %v", err)
	}
	if privatePayload.ClientID != "client_alice" || privatePayload.Scheme != sdk.CryptoEnvelopeHPKEV1 {
		t.Fatalf("unexpected private key payload: %+v", privatePayload)
	}
	publicPayload, err := readPublicKeyFile(publicPath)
	if err != nil {
		t.Fatalf("read public key: %v", err)
	}
	derived, err := sdk.DeriveX25519RecipientPublicKey("client_alice", privateKey)
	if err != nil {
		t.Fatalf("derive public key: %v", err)
	}
	if !bytes.Equal(publicPayload.PublicKey, derived.PublicKey) {
		t.Fatalf("public key does not match private key")
	}
	info, err := os.Stat(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != keyFileMode {
		t.Fatalf("private key mode = %v, want %v", got, keyFileMode)
	}
}

func TestKeyGenerateRefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	privatePath := filepath.Join(dir, "client_alice.x25519.json")
	publicPath := filepath.Join(dir, "client_alice.x25519.pub.json")
	if err := os.WriteFile(privatePath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := (&app{stdout: &stdout, stderr: &stderr}).run([]string{"key", "generate", "--client-id", "client_alice", "--private-key-out", privatePath, "--public-key-out", publicPath})
	if code == 0 {
		t.Fatalf("expected overwrite failure")
	}
	if !strings.Contains(stderr.String(), "write") {
		t.Fatalf("expected overwrite error, got: %s", stderr.String())
	}
}

func TestRecipientSpecSupportsExplicitAndEmbeddedClientIDs(t *testing.T) {
	dir := t.TempDir()
	privateKey := bytes.Repeat([]byte{7}, 32)
	publicPath := filepath.Join(dir, "client_bob.pub.json")
	if err := writePublicKey("client_bob", privateKey, publicPath); err != nil {
		t.Fatal(err)
	}
	clientID, publicKey, err := readRecipientSpec("client_bob=" + publicPath)
	if err != nil {
		t.Fatalf("read explicit recipient: %v", err)
	}
	if clientID != "client_bob" || publicKey.ClientID != "client_bob" {
		t.Fatalf("unexpected explicit recipient: %q %+v", clientID, publicKey)
	}
	clientID, publicKey, err = readRecipientSpec(publicPath)
	if err != nil {
		t.Fatalf("read embedded recipient: %v", err)
	}
	if clientID != "client_bob" || publicKey.ClientID != "client_bob" {
		t.Fatalf("unexpected embedded recipient: %q %+v", clientID, publicKey)
	}
}

func TestWritePublicKeyUsesDocumentedJSONShape(t *testing.T) {
	dir := t.TempDir()
	privateKey := bytes.Repeat([]byte{9}, 32)
	publicPath := filepath.Join(dir, "client_carol.pub.json")
	if err := writePublicKey("client_carol", privateKey, publicPath); err != nil {
		t.Fatal(err)
	}
	var payload map[string]string
	body, err := os.ReadFile(publicPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["client_id"] != "client_carol" || payload["scheme"] != sdk.CryptoEnvelopeHPKEV1 || !strings.HasPrefix(payload["fingerprint"], "sha256:") {
		t.Fatalf("unexpected public key json: %v", payload)
	}
	if _, err := base64.StdEncoding.DecodeString(payload["public_key_b64"]); err != nil {
		t.Fatalf("invalid public key base64: %v", err)
	}
}

func TestHelpMentionsEncryptedSecretCommands(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := (&app{stdout: &stdout, stderr: &stderr}).run([]string{"help"})
	if code != 0 {
		t.Fatalf("help failed: %d %s", code, stderr.String())
	}
	body := stdout.String()
	for _, token := range []string{"secret put", "secret get", "secret share", "secret delete", "secret version put", "secret versions", "secret access list", "secret access revoke", "Secret payloads are encrypted/decrypted locally"} {
		if !strings.Contains(body, token) {
			t.Fatalf("help missing %q: %s", token, body)
		}
	}
}

func TestMetadataListCommandsRequireSecretIDBeforeTransport(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{name: "versions", args: []string{"secret", "versions"}},
		{name: "access list", args: []string{"secret", "access", "list"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := (&app{stdout: &stdout, stderr: &stderr}).run(tc.args)
			if code != 2 {
				t.Fatalf("expected usage failure, got %d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
			if !strings.Contains(stderr.String(), "--secret-id is required") {
				t.Fatalf("expected secret id error, got: %s", stderr.String())
			}
		})
	}
}

func TestDestructiveSecretCommandsRequireExplicitConfirmation(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{name: "secret delete", args: []string{"secret", "delete", "--secret-id", "00000000-0000-0000-0000-000000000001"}, want: "--yes is required to delete a secret"},
		{name: "access revoke", args: []string{"secret", "access", "revoke", "--secret-id", "00000000-0000-0000-0000-000000000001", "--target-client-id", "client_bob"}, want: "--yes is required to revoke secret access"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := (&app{stdout: &stdout, stderr: &stderr}).run(tc.args)
			if code != 2 {
				t.Fatalf("expected confirmation failure, got %d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
			if !strings.Contains(stderr.String(), tc.want) {
				t.Fatalf("expected %q, got: %s", tc.want, stderr.String())
			}
		})
	}
}

func TestDestructiveSecretCommandsRequireTransportAfterConfirmation(t *testing.T) {
	for _, args := range [][]string{
		{"secret", "delete", "--secret-id", "00000000-0000-0000-0000-000000000001", "--yes"},
		{"secret", "access", "revoke", "--secret-id", "00000000-0000-0000-0000-000000000001", "--target-client-id", "client_bob", "--yes"},
	} {
		var stdout, stderr bytes.Buffer
		code := (&app{stdout: &stdout, stderr: &stderr}).run(args)
		if code != 1 {
			t.Fatalf("expected transport failure, got %d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
		if !strings.Contains(stderr.String(), "--server-url, --cert, --key and --ca are required") {
			t.Fatalf("expected mTLS option error, got: %s", stderr.String())
		}
	}
}

func TestTransportClientRequiresMTLSOptions(t *testing.T) {
	_, err := buildTransportClient(transportFlags{serverURL: "https://127.0.0.1:8443"})
	if err == nil || !strings.Contains(err.Error(), "--server-url, --cert, --key and --ca are required") {
		t.Fatalf("expected mTLS option error, got: %v", err)
	}
}
