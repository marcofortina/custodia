// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"custodia/internal/certutil"
)

func TestClientDoctorOfflineValidatesProfile(t *testing.T) {
	dir := t.TempDir()
	artifacts, err := certutil.GenerateLiteBootstrap(certutil.LiteBootstrapRequest{AdminClientID: "client_alice", ServerName: "localhost"})
	if err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(dir, "ca.crt")
	certPath := filepath.Join(dir, "client.crt")
	keyPath := filepath.Join(dir, "client.key")
	for path, body := range map[string][]byte{caPath: artifacts.CACertPEM, certPath: artifacts.AdminCertPEM, keyPath: artifacts.AdminKeyPEM} {
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cryptoKeyPath := filepath.Join(dir, "client_alice.x25519.json")
	publicKeyPath := filepath.Join(dir, "client_alice.x25519.pub.json")
	if code := (&app{stdout: ioDiscard{}, stderr: ioDiscard{}}).run([]string{"key", "generate", "--client-id", "client_alice", "--private-key-out", cryptoKeyPath, "--public-key-out", publicKeyPath}); code != 0 {
		t.Fatalf("key generate failed with %d", code)
	}
	configPath := filepath.Join(dir, "client.config.json")
	if err := writeJSONFileExclusive(configPath, clientConfigFile{ServerURL: "https://localhost:8443", CertFile: certPath, KeyFile: keyPath, CAFile: caPath, ClientID: "client_alice", CryptoKey: cryptoKeyPath}, keyFileMode); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := (&app{stdout: &stdout, stderr: &stderr}).run([]string{"doctor", "--config", configPath})
	if code != 0 {
		t.Fatalf("doctor failed with %d stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	for _, token := range []string{"Custodia client doctor", "[OK] mTLS certificate/key", "[OK] CA bundle", "[OK] derived public key", "[WARN] online server check: skipped"} {
		if !strings.Contains(stdout.String(), token) {
			t.Fatalf("expected %q in output: %s", token, stdout.String())
		}
	}
}

func TestClientDoctorOnlineUsesNonAdminMeEndpoint(t *testing.T) {
	dir := t.TempDir()
	artifacts, err := certutil.GenerateLiteBootstrap(certutil.LiteBootstrapRequest{AdminClientID: "client_alice", ServerName: "localhost"})
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, "client.crt")
	keyPath := filepath.Join(dir, "client.key")
	for path, body := range map[string][]byte{certPath: artifacts.AdminCertPEM, keyPath: artifacts.AdminKeyPEM} {
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.EscapedPath() != "/v1/me" {
			t.Fatalf("unexpected online doctor request: %s %s", r.Method, r.URL.EscapedPath())
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"client_id":"client_alice","mtls_subject":"CN=client_alice","is_active":true,"created_at":"2026-01-01T00:00:00Z"}`))
	}))
	defer server.Close()

	caPath := filepath.Join(dir, "ca.crt")
	serverCert := server.Certificate()
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCert.Raw})
	if _, err := x509.ParseCertificate(serverCert.Raw); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	configPath := filepath.Join(dir, "client.config.json")
	if err := writeJSONFileExclusive(configPath, clientConfigFile{ServerURL: server.URL, CertFile: certPath, KeyFile: keyPath, CAFile: caPath, ClientID: "client_alice"}, keyFileMode); err != nil {
		t.Fatal(err)
	}
	finding := checkClientDoctorOnline(configPath)
	if finding.Status != clientDoctorOK || finding.Message != "client_alice" {
		t.Fatalf("unexpected online finding: %+v", finding)
	}
}

func TestClientDoctorRequiresConfig(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := (&app{stdout: &stdout, stderr: &stderr}).run([]string{"doctor"})
	if code != 2 {
		t.Fatalf("expected usage failure, got %d", code)
	}
	if !strings.Contains(stderr.String(), "--client-id or --config is required") {
		t.Fatalf("expected config error, got %s", stderr.String())
	}
}

func TestClientDoctorRejectsHTTPURL(t *testing.T) {
	finding := checkClientDoctorServerURL("http://localhost:8443")
	if finding.Status != clientDoctorFail {
		t.Fatalf("expected failure, got %+v", finding)
	}
}

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) { return len(p), nil }
