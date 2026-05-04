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
	"testing"
	"time"

	"custodia/internal/signeraudit"
	"custodia/internal/signing"
)

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
