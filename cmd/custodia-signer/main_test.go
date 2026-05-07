// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"custodia/internal/signeraudit"
	"custodia/internal/signing"
)

func TestSignerInfoCommandsDoNotLoadRuntimeConfig(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{name: "version", args: []string{"version"}, want: "dev unknown unknown\n"},
		{name: "long version", args: []string{"--version"}, want: "dev unknown unknown\n"},
		{name: "help", args: []string{"help"}, want: "Usage:\n  custodia-signer"},
		{name: "short help", args: []string{"-h"}, want: "Usage:\n  custodia-signer"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			handled, code := handleInfoCommand(tc.args, &out)
			if !handled || code != 0 {
				t.Fatalf("handled=%v code=%d", handled, code)
			}
			if !strings.Contains(out.String(), tc.want) {
				t.Fatalf("expected %q in %q", tc.want, out.String())
			}
		})
	}
}

func TestSignerInfoCommandsIgnoreRuntimeArgs(t *testing.T) {
	var out bytes.Buffer
	handled, code := handleInfoCommand([]string{"--ca-cert", "missing.pem"}, &out)
	if handled || code != 0 || out.Len() != 0 {
		t.Fatalf("unexpected info handling: handled=%v code=%d out=%q", handled, code, out.String())
	}
}

func TestSignerRequiresAdminSubject(t *testing.T) {
	handler := testSignerHandler(t)
	req := httptest.NewRequest(http.MethodPost, "/v1/certificates/sign", bytes.NewBufferString(`{}`))
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", res.Code, http.StatusForbidden)
	}
}

func TestSignerSignsClientCertificate(t *testing.T) {
	handler := testSignerHandler(t)
	payload, err := json.Marshal(signing.SignClientCertificateRequest{
		ClientID: "client_alice",
		CSRPem:   string(testSignerCSR(t, "client_alice")),
		TTLHours: 1,
	})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/certificates/sign", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Custodia-Signer-Admin-Subject", "signer_admin")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", res.Code, res.Body.String())
	}
	var issued signing.SignClientCertificateResponse
	if err := json.NewDecoder(res.Body).Decode(&issued); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	block, _ := pem.Decode([]byte(issued.CertificatePEM))
	if block == nil {
		t.Fatal("missing issued certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}
	if cert.Subject.CommonName != "client_alice" {
		t.Fatalf("CommonName = %q", cert.Subject.CommonName)
	}
}

func testSignerHandler(t *testing.T) http.Handler {
	t.Helper()
	caCertPEM, caKeyPEM := testSignerCA(t)
	clientSigner, err := signing.NewClientCertificateSigner(caCertPEM, caKeyPEM)
	if err != nil {
		t.Fatalf("NewClientCertificateSigner() error = %v", err)
	}
	return newSignerServer(clientSigner, map[string]bool{"signer_admin": true}, 1, true, signeraudit.NopRecorder{}, "")
}

func testSignerCA(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: "custodia-signer-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey() error = %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func testSignerCSR(t *testing.T, clientID string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: clientID},
		DNSNames: []string{clientID},
	}, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest() error = %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func TestSignerPropagatesRequestID(t *testing.T) {
	handler := testSignerHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Header.Set("X-Request-ID", "signer-trace-1")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if got := res.Header().Get("X-Request-ID"); got != "signer-trace-1" {
		t.Fatalf("expected propagated request id, got %q", got)
	}
}

func TestSignerGeneratesRequestID(t *testing.T) {
	handler := testSignerHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if got := res.Header().Get("X-Request-ID"); got == "" {
		t.Fatal("expected generated request id")
	}
}

func TestSignerAuditsCertificateRequests(t *testing.T) {
	path := t.TempDir() + "/signer-audit.jsonl"
	recorder, err := signeraudit.NewJSONLRecorder(path)
	if err != nil {
		t.Fatalf("NewJSONLRecorder() error = %v", err)
	}
	defer recorder.Close()
	caCertPEM, caKeyPEM := testSignerCA(t)
	clientSigner, err := signing.NewClientCertificateSigner(caCertPEM, caKeyPEM)
	if err != nil {
		t.Fatalf("NewClientCertificateSigner() error = %v", err)
	}
	handler := newSignerServer(clientSigner, map[string]bool{"signer_admin": true}, 1, true, recorder, "")
	payload, err := json.Marshal(signing.SignClientCertificateRequest{ClientID: "client_alice", CSRPem: string(testSignerCSR(t, "client_alice")), TTLHours: 1})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/certificates/sign", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Custodia-Signer-Admin-Subject", "signer_admin")
	req.Header.Set("X-Request-ID", "signer-audit-trace")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", res.Code, res.Body.String())
	}
	payloadBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if !bytes.Contains(payloadBytes, []byte(`"action":"certificate.sign"`)) || !bytes.Contains(payloadBytes, []byte(`"request_id":"signer-audit-trace"`)) || !bytes.Contains(payloadBytes, []byte(`"client_id":"client_alice"`)) {
		t.Fatalf("unexpected audit payload: %s", string(payloadBytes))
	}
}

func TestLoadConfigWithArgsReadsSignerYAMLAndEnvOverrides(t *testing.T) {
	path := t.TempDir() + "/custodia-signer.yaml"
	payload := []byte(`addr: ":9444"
tls_cert_file: /etc/custodia/server.crt
tls_key_file: /etc/custodia/server.key
client_ca_file: /etc/custodia/client-ca.crt
ca_cert_file: /etc/custodia/ca.crt
ca_key_file: /etc/custodia/ca.key
ca_key_passphrase_file: /etc/custodia/ca.pass
key_provider: file
admin_subjects: admin, signer_admin
default_ttl_hours: 12
dev_insecure_http: false
shutdown_timeout_seconds: 7
audit_log_file: /var/log/custodia/signer-audit.jsonl
crl_file: /etc/custodia/client.crl.pem
`)
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CUSTODIA_SIGNER_ADDR", ":9555")
	t.Setenv("CUSTODIA_SIGNER_KEY_PROVIDER", signing.KeyProviderPKCS11)
	cfg, err := loadConfigWithArgs([]string{"--config", path})
	if err != nil {
		t.Fatalf("loadConfigWithArgs() error = %v", err)
	}
	if cfg.addr != ":9555" {
		t.Fatalf("env addr override = %q", cfg.addr)
	}
	if cfg.keyProvider != signing.KeyProviderPKCS11 {
		t.Fatalf("env key provider override = %q", cfg.keyProvider)
	}
	if cfg.tlsCertFile != "/etc/custodia/server.crt" || cfg.caKeyPassphraseFile != "/etc/custodia/ca.pass" || cfg.auditLogFile != "/var/log/custodia/signer-audit.jsonl" || cfg.crlFile != "/etc/custodia/client.crl.pem" {
		t.Fatalf("unexpected file config: %+v", cfg)
	}
	if !cfg.adminSubjects["admin"] || !cfg.adminSubjects["signer_admin"] {
		t.Fatalf("unexpected admin subjects: %+v", cfg.adminSubjects)
	}
	if cfg.defaultTTLHours != 12 || cfg.shutdownTimeout != 7*time.Second {
		t.Fatalf("unexpected durations: ttl=%d shutdown=%s", cfg.defaultTTLHours, cfg.shutdownTimeout)
	}
}

func TestLoadConfigWithArgsReadsDeployExampleSignerYAML(t *testing.T) {
	cfg, err := loadConfigWithArgs([]string{"--config", "../../deploy/examples/custodia-signer.yaml"})
	if err != nil {
		t.Fatalf("loadConfigWithArgs() error = %v", err)
	}
	if cfg.addr != ":9444" || cfg.tlsCertFile == "" || cfg.tlsKeyFile == "" || cfg.clientCAFile == "" {
		t.Fatalf("expected listener and TLS fields from deploy example: %+v", cfg)
	}
	if !cfg.adminSubjects["admin"] || cfg.caCertFile == "" || cfg.caKeyFile == "" || cfg.auditLogFile == "" || cfg.crlFile == "" {
		t.Fatalf("unexpected deploy example signer config: %+v", cfg)
	}
}

func TestDeployExampleSignerConfigAvoidsLegacyFlatRuntimeKeys(t *testing.T) {
	payload, err := os.ReadFile("../../deploy/examples/custodia-signer.yaml")
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	for _, key := range []string{
		"addr:",
		"tls_cert_file:",
		"tls_key_file:",
		"client_ca_file:",
		"ca_cert_file:",
		"ca_key_file:",
		"ca_key_passphrase_file:",
		"key_provider:",
		"pkcs11_sign_command:",
		"admin_subjects:",
		"default_ttl_hours:",
		"shutdown_timeout_seconds:",
		"audit_log_file:",
		"crl_file:",
	} {
		if hasTopLevelSignerYAMLKey(string(payload), key) {
			t.Fatalf("deploy signer example still uses flat scalar key %q:\n%s", key, payload)
		}
	}
}

func hasTopLevelSignerYAMLKey(payload, key string) bool {
	for _, line := range strings.Split(payload, "\n") {
		if strings.HasPrefix(line, key) {
			return true
		}
	}
	return false
}

func TestLoadConfigWithArgsReadsStructuredSignerYAML(t *testing.T) {
	path := t.TempDir() + "/custodia-signer.yaml"
	payload := []byte(`server:
  addr: ":9444"
  default_ttl_hours: 12
  shutdown_timeout_seconds: 7
tls:
  cert_file: /etc/custodia/server.crt
  key_file: /etc/custodia/server.key
  client_ca_file: /etc/custodia/client-ca.crt
admin:
  subjects:
    - admin
    - signer_admin
ca:
  key_provider: file
  cert_file: /etc/custodia/ca.crt
  key_file: /etc/custodia/ca.key
  key_passphrase_file: /etc/custodia/ca.pass
audit:
  log_file: /var/log/custodia/signer-audit.jsonl
revocation:
  crl_file: /etc/custodia/client.crl.pem
`)
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfigWithArgs([]string{"--config", path})
	if err != nil {
		t.Fatalf("loadConfigWithArgs() error = %v", err)
	}
	if cfg.addr != ":9444" || cfg.defaultTTLHours != 12 || cfg.shutdownTimeout != 7*time.Second {
		t.Fatalf("unexpected server config: %+v", cfg)
	}
	if cfg.tlsCertFile != "/etc/custodia/server.crt" || cfg.tlsKeyFile != "/etc/custodia/server.key" || cfg.clientCAFile != "/etc/custodia/client-ca.crt" {
		t.Fatalf("unexpected tls config: %+v", cfg)
	}
	if !cfg.adminSubjects["admin"] || !cfg.adminSubjects["signer_admin"] {
		t.Fatalf("unexpected admin subjects: %+v", cfg.adminSubjects)
	}
	if cfg.caCertFile != "/etc/custodia/ca.crt" || cfg.caKeyFile != "/etc/custodia/ca.key" || cfg.caKeyPassphraseFile != "/etc/custodia/ca.pass" || cfg.keyProvider != signing.KeyProviderFile {
		t.Fatalf("unexpected ca config: %+v", cfg)
	}
	if cfg.auditLogFile != "/var/log/custodia/signer-audit.jsonl" || cfg.crlFile != "/etc/custodia/client.crl.pem" {
		t.Fatalf("unexpected audit/revocation config: %+v", cfg)
	}
}

func TestLoadConfigWithArgsRejectsUnsupportedStructuredSignerYAML(t *testing.T) {
	path := t.TempDir() + "/custodia-signer.yaml"
	if err := os.WriteFile(path, []byte("key_provider:\n  name: file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfigWithArgs([]string{"--config", path}); err == nil {
		t.Fatal("expected unsupported structured signer yaml error")
	}
}

func TestLoadConfigWithArgsRejectsUnsupportedSignerYAML(t *testing.T) {
	path := t.TempDir() + "/custodia-signer.yaml"
	if err := os.WriteFile(path, []byte("nested:\n  value: no\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfigWithArgs([]string{"--config", path}); err == nil {
		t.Fatal("expected unsupported YAML error")
	}
}

func TestLoadConfigWithArgsRejectsUnknownSignerKey(t *testing.T) {
	path := t.TempDir() + "/custodia-signer.yaml"
	if err := os.WriteFile(path, []byte("unknown_key: nope\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfigWithArgs([]string{"--config", path}); err == nil || !strings.Contains(err.Error(), "unknown signer config key") {
		t.Fatalf("expected unknown key error, got %v", err)
	}
}

func TestLoadConfigDefaultsSignerKeyProviderToFile(t *testing.T) {
	t.Setenv("CUSTODIA_SIGNER_KEY_PROVIDER", "")
	cfg := loadConfig()
	if cfg.keyProvider != signing.KeyProviderFile {
		t.Fatalf("keyProvider = %q, want %q", cfg.keyProvider, signing.KeyProviderFile)
	}
}

func TestLoadConfigReadsSignerKeyProvider(t *testing.T) {
	t.Setenv("CUSTODIA_SIGNER_KEY_PROVIDER", signing.KeyProviderPKCS11)
	cfg := loadConfig()
	if cfg.keyProvider != signing.KeyProviderPKCS11 {
		t.Fatalf("keyProvider = %q, want %q", cfg.keyProvider, signing.KeyProviderPKCS11)
	}
}

func TestSignerServesConfiguredCRL(t *testing.T) {
	crlPath := t.TempDir() + "/client.crl"
	if err := os.WriteFile(crlPath, testSignerCRL(t), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	handler := testSignerHandlerWithCRL(t, crlPath)
	req := httptest.NewRequest(http.MethodGet, "/v1/crl.pem", nil)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", res.Code, res.Body.String())
	}
	if got := res.Header().Get("Content-Type"); got != "application/pkix-crl" {
		t.Fatalf("content type = %q", got)
	}
	if got := res.Header().Get("X-Custodia-CRL-Revoked-Count"); got != "1" {
		t.Fatalf("revoked count header = %q", got)
	}
	if !bytes.Contains(res.Body.Bytes(), []byte("BEGIN X509 CRL")) {
		t.Fatalf("missing CRL PEM body: %s", res.Body.String())
	}
}

func TestSignerCRLReturnsNotFoundWhenUnconfigured(t *testing.T) {
	handler := testSignerHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/crl.pem", nil)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", res.Code, http.StatusNotFound)
	}
}

func testSignerHandlerWithCRL(t *testing.T, crlPath string) http.Handler {
	t.Helper()
	caCertPEM, caKeyPEM := testSignerCA(t)
	clientSigner, err := signing.NewClientCertificateSigner(caCertPEM, caKeyPEM)
	if err != nil {
		t.Fatalf("NewClientCertificateSigner() error = %v", err)
	}
	return newSignerServer(clientSigner, map[string]bool{"signer_admin": true}, 1, true, signeraudit.NopRecorder{}, crlPath)
}

func testSignerCRL(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	now := time.Now().UTC()
	ca := &x509.Certificate{
		SerialNumber:          big.NewInt(99),
		Subject:               pkix.Name{CommonName: "crl-test-ca"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId:          []byte{9, 9, 9},
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		Number:             big.NewInt(1),
		ThisUpdate:         now,
		NextUpdate:         now.Add(time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{{
			SerialNumber:   big.NewInt(100),
			RevocationTime: now,
		}},
	}, ca, key)
	if err != nil {
		t.Fatalf("CreateRevocationList() error = %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})
}

func TestLoadConfigReadsPKCS11Command(t *testing.T) {
	t.Setenv("CUSTODIA_SIGNER_KEY_PROVIDER", "pkcs11")
	t.Setenv("CUSTODIA_SIGNER_PKCS11_SIGN_COMMAND", "/usr/local/bin/pkcs11-sign")
	cfg := loadConfig()
	if cfg.keyProvider != "pkcs11" {
		t.Fatalf("keyProvider = %q", cfg.keyProvider)
	}
	if cfg.pkcs11SignCommand != "/usr/local/bin/pkcs11-sign" {
		t.Fatalf("pkcs11SignCommand = %q", cfg.pkcs11SignCommand)
	}
}

func TestSignerRevocationSerialStatus(t *testing.T) {
	crlPath := t.TempDir() + "/client.crl"
	if err := os.WriteFile(crlPath, testSignerCRL(t), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	handler := testSignerHandlerWithCRL(t, crlPath)
	req := httptest.NewRequest(http.MethodGet, "/v1/revocation/serial?serial_hex=64", nil)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", res.Code, res.Body.String())
	}
	if !bytes.Contains(res.Body.Bytes(), []byte(`"status":"revoked"`)) || !bytes.Contains(res.Body.Bytes(), []byte(`"serial_hex":"64"`)) {
		t.Fatalf("unexpected revocation status: %s", res.Body.String())
	}
}

func TestSignerRevocationSerialStatusRejectsInvalidSerial(t *testing.T) {
	crlPath := t.TempDir() + "/client.crl"
	if err := os.WriteFile(crlPath, testSignerCRL(t), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	handler := testSignerHandlerWithCRL(t, crlPath)
	req := httptest.NewRequest(http.MethodGet, "/v1/revocation/serial?serial_hex=not-hex", nil)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", res.Code, http.StatusBadRequest)
	}
}

func TestLoadConfigReadsSignerCAKeyPassphraseFile(t *testing.T) {
	t.Setenv("CUSTODIA_SIGNER_CA_KEY_PASSPHRASE_FILE", "/etc/custodia/ca.pass")
	cfg := loadConfig()
	if cfg.caKeyPassphraseFile != "/etc/custodia/ca.pass" {
		t.Fatalf("caKeyPassphraseFile = %q", cfg.caKeyPassphraseFile)
	}
}

func TestSignerConfigValidateCommandAcceptsStructuredExample(t *testing.T) {
	var stdout, stderr strings.Builder
	handled, code := handleConfigCommand([]string{"config", "validate", "--config", "../../deploy/examples/custodia-signer.yaml"}, &stdout, &stderr)
	if !handled || code != 0 {
		t.Fatalf("expected config validate success, handled=%v code=%d stdout=%q stderr=%q", handled, code, stdout.String(), stderr.String())
	}
}

func TestSignerConfigValidateCommandRejectsMissingConfig(t *testing.T) {
	var stdout, stderr strings.Builder
	handled, code := handleConfigCommand([]string{"config", "validate"}, &stdout, &stderr)
	if !handled || code != 2 {
		t.Fatalf("expected config validate usage failure, handled=%v code=%d", handled, code)
	}
	if !strings.Contains(stderr.String(), "--config is required") {
		t.Fatalf("unexpected stderr: %s", stderr.String())
	}
}

func TestSignerConfigRenderCommandEmitsStructuredYAML(t *testing.T) {
	var stdout, stderr strings.Builder
	handled, code := handleConfigCommand([]string{"config", "render"}, &stdout, &stderr)
	if !handled || code != 0 {
		t.Fatalf("expected config render success, handled=%v code=%d stderr=%q", handled, code, stderr.String())
	}
	body := stdout.String()
	for _, want := range []string{"server:", "tls:", "admin:", "subjects:", "ca:"} {
		if !strings.Contains(body, want) {
			t.Fatalf("rendered config missing %q: %s", want, body)
		}
	}
}
