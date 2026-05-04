// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package crldist

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"testing"
	"time"
)

func TestLoadPEMReadsValidCRL(t *testing.T) {
	path := t.TempDir() + "/client.crl"
	payload := testCRL(t)
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	loaded, list, err := LoadPEM(path)
	if err != nil {
		t.Fatalf("LoadPEM() error = %v", err)
	}
	if string(loaded) != string(payload) {
		t.Fatal("loaded payload mismatch")
	}
	if len(list.RevokedCertificateEntries) != 1 {
		t.Fatalf("revoked entries = %d", len(list.RevokedCertificateEntries))
	}
}

func TestLoadPEMRejectsInvalidCRL(t *testing.T) {
	path := t.TempDir() + "/client.crl"
	if err := os.WriteFile(path, []byte("not pem"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	_, _, err := LoadPEM(path)
	if !errors.Is(err, ErrInvalidCRL) {
		t.Fatalf("LoadPEM() error = %v, want %v", err, ErrInvalidCRL)
	}
}

func testCRL(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	now := time.Now().UTC()
	ca := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "crl-test-ca"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId:          []byte{1, 2, 3, 4},
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		SignatureAlgorithm: x509.SHA256WithRSA,
		Number:             big.NewInt(1),
		ThisUpdate:         now,
		NextUpdate:         now.Add(time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{{
			SerialNumber:   big.NewInt(42),
			RevocationTime: now,
		}},
	}, ca, key)
	if err != nil {
		t.Fatalf("CreateRevocationList() error = %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})
}
