// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunDoctorOfflinePassesWithStructuredConfigs(t *testing.T) {
	dir := t.TempDir()
	writeDoctorFile(t, filepath.Join(dir, "server.crt"), 0o644)
	writeDoctorFile(t, filepath.Join(dir, "server.key"), 0o600)
	writeDoctorFile(t, filepath.Join(dir, "client-ca.crt"), 0o644)
	writeDoctorFile(t, filepath.Join(dir, "client.crl.pem"), 0o644)
	writeDoctorFile(t, filepath.Join(dir, "ca.crt"), 0o644)
	writeDoctorFile(t, filepath.Join(dir, "ca.key"), 0o600)
	writeDoctorFile(t, filepath.Join(dir, "ca.pass"), 0o600)
	dbDir := filepath.Join(dir, "db")
	logDir := filepath.Join(dir, "log")
	if err := os.MkdirAll(dbDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(logDir, 0o750); err != nil {
		t.Fatal(err)
	}
	serverConfig := filepath.Join(dir, "custodia-server.yaml")
	serverYAML := `profile: lite
server:
  api_addr: ":8443"
  web_addr: ":9443"
  log_file: ` + filepath.Join(logDir, "custodia.log") + `
storage:
  backend: sqlite
  database_url: "file:` + filepath.Join(dbDir, "custodia.db") + `"
rate_limit:
  backend: memory
web:
  mfa_required: true
tls:
  cert_file: ` + filepath.Join(dir, "server.crt") + `
  key_file: ` + filepath.Join(dir, "server.key") + `
  client_ca_file: ` + filepath.Join(dir, "client-ca.crt") + `
  client_crl_file: ` + filepath.Join(dir, "client.crl.pem") + `
signer:
  key_provider: file
  ca_cert_file: ` + filepath.Join(dir, "ca.crt") + `
  ca_key_file: ` + filepath.Join(dir, "ca.key") + `
  ca_key_passphrase_file: ` + filepath.Join(dir, "ca.pass") + `
`
	if err := os.WriteFile(serverConfig, []byte(serverYAML), 0o640); err != nil {
		t.Fatal(err)
	}
	signerConfig := filepath.Join(dir, "custodia-signer.yaml")
	signerYAML := `server:
  addr: ":9444"
tls:
  cert_file: ` + filepath.Join(dir, "server.crt") + `
  key_file: ` + filepath.Join(dir, "server.key") + `
  client_ca_file: ` + filepath.Join(dir, "client-ca.crt") + `
admin:
  subjects:
    - admin
ca:
  key_provider: file
  cert_file: ` + filepath.Join(dir, "ca.crt") + `
  key_file: ` + filepath.Join(dir, "ca.key") + `
  key_passphrase_file: ` + filepath.Join(dir, "ca.pass") + `
revocation:
  crl_file: ` + filepath.Join(dir, "client.crl.pem") + `
audit:
  log_file: ` + filepath.Join(logDir, "signer-audit.jsonl") + `
`
	if err := os.WriteFile(signerConfig, []byte(signerYAML), 0o640); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err := runDoctorWithOptions(doctorOptions{serverConfig: serverConfig, signerConfig: signerConfig, out: &out})
	if err != nil {
		t.Fatalf("runDoctorWithOptions() error = %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "Result: ok") {
		t.Fatalf("expected ok output, got: %s", out.String())
	}
}

func TestRunDoctorOfflineFailsOnOpenSensitiveKey(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "ca.key")
	writeDoctorFile(t, keyPath, 0o644)
	finding := checkReadableFile("signer CA key", keyPath, true, true)
	if finding.Status != doctorFail || !strings.Contains(finding.Message, "too open") {
		t.Fatalf("expected open key failure, got: %+v", finding)
	}
}

func TestLoadDoctorSignerConfigReadsStructuredSubjects(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "signer.yaml")
	body := `server:
  addr: ":9444"
admin:
  subjects:
    - admin
    - ops
ca:
  cert_file: /etc/custodia/ca.crt
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadDoctorSignerConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Addr != ":9444" || strings.Join(cfg.AdminSubjects, ",") != "admin,ops" || cfg.CACertFile != "/etc/custodia/ca.crt" {
		t.Fatalf("unexpected signer config: %+v", cfg)
	}
}

func writeDoctorFile(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte("test"), mode); err != nil {
		t.Fatal(err)
	}
}

func TestNormalizeDoctorDialAddr(t *testing.T) {
	for _, tc := range []struct {
		addr string
		want string
	}{
		{addr: ":8443", want: "127.0.0.1:8443"},
		{addr: "0.0.0.0:9444", want: "127.0.0.1:9444"},
		{addr: "localhost:9443", want: "localhost:9443"},
	} {
		got, err := normalizeDoctorDialAddr(tc.addr)
		if err != nil {
			t.Fatalf("normalizeDoctorDialAddr(%q) error = %v", tc.addr, err)
		}
		if got != tc.want {
			t.Fatalf("normalizeDoctorDialAddr(%q) = %q, want %q", tc.addr, got, tc.want)
		}
	}
}

func TestRunDoctorOfflineDoesNotCheckSystemdOrNetworkByDefault(t *testing.T) {
	var out bytes.Buffer
	err := runDoctorWithOptions(doctorOptions{serverConfig: "", signerConfig: "", out: &out})
	if err == nil {
		t.Fatal("expected doctor failure for missing configs")
	}
	if strings.Contains(out.String(), "systemd") || strings.Contains(out.String(), "listener") {
		t.Fatalf("offline doctor unexpectedly checked systemd/network: %s", out.String())
	}
}
