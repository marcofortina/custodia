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
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"custodia/internal/certutil"

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

func TestKeyGenerateUsesDefaultClientProfile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	var stdout, stderr bytes.Buffer
	code := (&app{stdout: &stdout, stderr: &stderr}).run([]string{"key", "generate", "--client-id", "client_alice"})
	if code != 0 {
		t.Fatalf("key generate failed with %d: %s", code, stderr.String())
	}
	profile := filepath.Join(dir, "custodia", "client_alice")
	for _, path := range []string{filepath.Join(profile, "client_alice.x25519.json"), filepath.Join(profile, "client_alice.x25519.pub.json")} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected %s: %v", path, err)
		}
	}
	info, err := os.Stat(profile)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Fatalf("profile dir mode = %o, want 700", got)
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

func TestKeyInspectReportsLocalPublicFingerprint(t *testing.T) {
	dir := t.TempDir()
	privatePath := filepath.Join(dir, "client_alice.x25519.json")
	publicPath := filepath.Join(dir, "client_alice.x25519.pub.json")
	var stdout, stderr bytes.Buffer
	if code := (&app{stdout: &stdout, stderr: &stderr}).run([]string{"key", "generate", "--client-id", "client_alice", "--private-key-out", privatePath, "--public-key-out", publicPath}); code != 0 {
		t.Fatalf("key generate failed with %d: %s", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := (&app{stdout: &stdout, stderr: &stderr}).run([]string{"key", "inspect", "--key", privatePath}); code != 0 {
		t.Fatalf("key inspect failed with %d: %s", code, stderr.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("inspect output is not json: %v", err)
	}
	if payload["client_id"] != "client_alice" || payload["scheme"] != sdk.CryptoEnvelopeHPKEV1 || !strings.HasPrefix(payload["public_key_fingerprint"].(string), "sha256:") {
		t.Fatalf("unexpected inspect payload: %v", payload)
	}
}

func TestConfigWriteCreatesReusableClientConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "client.json")
	var stdout, stderr bytes.Buffer
	code := (&app{stdout: &stdout, stderr: &stderr}).run([]string{
		"config", "write",
		"--out", configPath,
		"--server-url", "https://vault.example:8443",
		"--cert", "client.crt",
		"--key", "client.key",
		"--ca", "ca.crt",
		"--client-id", "client_alice",
		"--crypto-key", "client_alice.x25519.json",
	})
	if code != 0 {
		t.Fatalf("config write failed with %d: %s", code, stderr.String())
	}
	config, err := readClientConfigFile(configPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if config.ServerURL != "https://vault.example:8443" || config.CertFile != "client.crt" || config.KeyFile != "client.key" || config.CAFile != "ca.crt" || config.ClientID != "client_alice" || config.CryptoKey != "client_alice.x25519.json" {
		t.Fatalf("unexpected config payload: %+v", config)
	}
	info, err := os.Stat(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != keyFileMode {
		t.Fatalf("config mode = %v, want %v", got, keyFileMode)
	}
}

func TestConfigWriteUsesDefaultClientProfile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	var stdout, stderr bytes.Buffer
	code := (&app{stdout: &stdout, stderr: &stderr}).run([]string{"config", "write", "--client-id", "client_alice", "--server-url", "https://vault.example:8443"})
	if code != 0 {
		t.Fatalf("config write failed with %d: %s", code, stderr.String())
	}
	profile := filepath.Join(dir, "custodia", "client_alice")
	config, err := readClientConfigFile(filepath.Join(profile, "client_alice.config.json"))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if config.CertFile != filepath.Join(profile, "client_alice.crt") || config.KeyFile != filepath.Join(profile, "client_alice.key") || config.CAFile != filepath.Join(profile, "ca.crt") || config.CryptoKey != filepath.Join(profile, "client_alice.x25519.json") {
		t.Fatalf("unexpected default config paths: %+v", config)
	}
}

func TestConfigCheckValidatesLocalFiles(t *testing.T) {
	dir := t.TempDir()
	artifacts, err := certutil.GenerateLiteBootstrap(certutil.LiteBootstrapRequest{AdminClientID: "client_alice", ServerName: "localhost"})
	if err != nil {
		t.Fatalf("GenerateLiteBootstrap() error = %v", err)
	}
	caPath := filepath.Join(dir, "ca.crt")
	certPath := filepath.Join(dir, "client.crt")
	keyPath := filepath.Join(dir, "client.key")
	for path, body := range map[string][]byte{caPath: artifacts.CACertPEM, certPath: artifacts.AdminCertPEM, keyPath: artifacts.AdminKeyPEM} {
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatalf("WriteFile(%s) error = %v", path, err)
		}
	}
	cryptoKeyPath := filepath.Join(dir, "client_alice.x25519.json")
	publicKeyPath := filepath.Join(dir, "client_alice.x25519.pub.json")
	if code := (&app{stdout: io.Discard, stderr: io.Discard}).run([]string{"key", "generate", "--client-id", "client_alice", "--private-key-out", cryptoKeyPath, "--public-key-out", publicKeyPath}); code != 0 {
		t.Fatalf("key generate failed with %d", code)
	}
	configPath := filepath.Join(dir, "client.config.json")
	if err := writeJSONFileExclusive(configPath, clientConfigFile{ServerURL: "https://localhost:8443", CertFile: certPath, KeyFile: keyPath, CAFile: caPath, ClientID: "client_alice", CryptoKey: cryptoKeyPath}, keyFileMode); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := (&app{stdout: &stdout, stderr: &stderr}).run([]string{"config", "check", "--config", configPath})
	if code != 0 {
		t.Fatalf("config check failed with %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"status": "ok"`) || !strings.Contains(stdout.String(), `"has_crypto_key": true`) {
		t.Fatalf("unexpected config check output: %s", stdout.String())
	}
}

func TestConfigCheckRejectsInvalidURLBeforeTransport(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "client.config.json")
	if err := writeJSONFileExclusive(configPath, clientConfigFile{ServerURL: "http://localhost:8443", CertFile: "client.crt", KeyFile: "client.key", CAFile: "ca.crt"}, keyFileMode); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := (&app{stdout: &stdout, stderr: &stderr}).run([]string{"config", "check", "--config", configPath})
	if code != 1 {
		t.Fatalf("expected config check failure, got %d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "server_url must be an https URL") {
		t.Fatalf("unexpected error: %s", stderr.String())
	}
}

func TestConfigFileMergesMissingTransportAndCryptoOptions(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "client.json")
	config := clientConfigFile{
		ServerURL: "https://vault.example:8443",
		CertFile:  "client.crt",
		KeyFile:   "client.key",
		CAFile:    "ca.crt",
		ClientID:  "client_alice",
		CryptoKey: "client_alice.x25519.json",
	}
	if err := writeJSONFileExclusive(configPath, config, keyFileMode); err != nil {
		t.Fatal(err)
	}
	transport := transportFlags{configFile: configPath}
	crypto := cryptoFlags{}
	if err := applyClientConfig(&transport, &crypto); err != nil {
		t.Fatalf("apply config: %v", err)
	}
	if transport.serverURL != config.ServerURL || transport.certFile != config.CertFile || transport.keyFile != config.KeyFile || transport.caFile != config.CAFile {
		t.Fatalf("transport config not merged: %+v", transport)
	}
	if crypto.clientID != config.ClientID || crypto.cryptoKey != config.CryptoKey {
		t.Fatalf("crypto config not merged: %+v", crypto)
	}
}

func TestConfigFileDoesNotOverrideExplicitOptions(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "client.json")
	config := clientConfigFile{ServerURL: "https://config.example:8443", CertFile: "config.crt", KeyFile: "config.key", CAFile: "config-ca.crt", ClientID: "config_client", CryptoKey: "config.x25519.json"}
	if err := writeJSONFileExclusive(configPath, config, keyFileMode); err != nil {
		t.Fatal(err)
	}
	transport := transportFlags{configFile: configPath, serverURL: "https://flag.example:8443", certFile: "flag.crt", keyFile: "flag.key", caFile: "flag-ca.crt"}
	crypto := cryptoFlags{clientID: "flag_client", cryptoKey: "flag.x25519.json"}
	if err := applyClientConfig(&transport, &crypto); err != nil {
		t.Fatalf("apply config: %v", err)
	}
	if transport.serverURL != "https://flag.example:8443" || transport.certFile != "flag.crt" || transport.keyFile != "flag.key" || transport.caFile != "flag-ca.crt" {
		t.Fatalf("explicit transport options were overwritten: %+v", transport)
	}
	if crypto.clientID != "flag_client" || crypto.cryptoKey != "flag.x25519.json" {
		t.Fatalf("explicit crypto options were overwritten: %+v", crypto)
	}
}

func TestHelpMentionsEncryptedSecretCommands(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := (&app{stdout: &stdout, stderr: &stderr}).run([]string{"help"})
	if code != 0 {
		t.Fatalf("help failed: %d %s", code, stderr.String())
	}
	body := stdout.String()
	for _, token := range []string{"config write", "config check", "doctor --client-id ID|--config FILE [--online]", "mtls install-cert", "key inspect", "--client-id ID", "secret put", "secret get", "secret update", "secret share", "secret delete", "secret versions", "secret access list", "secret access revoke", "Secret payloads are encrypted/decrypted locally"} {
		if !strings.Contains(body, token) {
			t.Fatalf("help missing %q: %s", token, body)
		}
	}
}

func TestMetadataListCommandsRequireKeyOrSecretIDBeforeTransport(t *testing.T) {
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
			if !strings.Contains(stderr.String(), "--key or --secret-id is required") {
				t.Fatalf("expected secret key error, got: %s", stderr.String())
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

func TestMTLSGenerateCSRWritesClientSideMaterial(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "client_alice.key")
	csrPath := filepath.Join(dir, "client_alice.csr")
	var stdout, stderr bytes.Buffer
	code := (&app{stdout: &stdout, stderr: &stderr}).run([]string{"mtls", "generate-csr", "--client-id", "client_alice", "--private-key-out", keyPath, "--csr-out", csrPath})
	if code != 0 {
		t.Fatalf("mtls generate-csr failed with %d: %s", code, stderr.String())
	}
	for path, wantMode := range map[string]os.FileMode{keyPath: keyFileMode, csrPath: publicFileMode} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("expected %s: %v", path, err)
		}
		if got := info.Mode().Perm(); got != wantMode {
			t.Fatalf("%s mode = %o, want %o", path, got, wantMode)
		}
	}
	stdout.Reset()
	stderr.Reset()
	code = (&app{stdout: &stdout, stderr: &stderr}).run([]string{"mtls", "generate-csr", "--client-id", "client_alice", "--private-key-out", keyPath, "--csr-out", csrPath})
	if code == 0 {
		t.Fatal("expected exclusive write failure")
	}
}

func TestMTLSGenerateCSRUsesDefaultClientProfile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	var stdout, stderr bytes.Buffer
	code := (&app{stdout: &stdout, stderr: &stderr}).run([]string{"mtls", "generate-csr", "--client-id", "client_alice"})
	if code != 0 {
		t.Fatalf("mtls generate-csr failed with %d: %s", code, stderr.String())
	}
	profile := filepath.Join(dir, "custodia", "client_alice")
	for path, wantMode := range map[string]os.FileMode{filepath.Join(profile, "client_alice.key"): keyFileMode, filepath.Join(profile, "client_alice.csr"): publicFileMode} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("expected %s: %v", path, err)
		}
		if got := info.Mode().Perm(); got != wantMode {
			t.Fatalf("%s mode = %o, want %o", path, got, wantMode)
		}
	}
}

func TestMTLSInstallCertUsesDefaultClientProfile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	certPath := filepath.Join(dir, "issued.crt")
	caPath := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(certPath, []byte("cert\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caPath, []byte("ca\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := (&app{stdout: &stdout, stderr: &stderr}).run([]string{"mtls", "install-cert", "--client-id", "client_alice", "--cert-file", certPath, "--ca-file", caPath})
	if code != 0 {
		t.Fatalf("mtls install-cert failed with %d: %s", code, stderr.String())
	}
	profile := filepath.Join(dir, "custodia", "client_alice")
	for _, path := range []string{filepath.Join(profile, "client_alice.crt"), filepath.Join(profile, "ca.crt")} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected %s: %v", path, err)
		}
	}
}

func TestMTLSGenerateCSRRejectsInvalidClientID(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := (&app{stdout: &stdout, stderr: &stderr}).run([]string{"mtls", "generate-csr", "--client-id", "client bad", "--private-key-out", filepath.Join(dir, "client.key"), "--csr-out", filepath.Join(dir, "client.csr")})
	if code == 0 {
		t.Fatal("expected invalid client id failure")
	}
}
