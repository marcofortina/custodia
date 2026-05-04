// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package certutil

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"
)

func TestGenerateClientCSR(t *testing.T) {
	csr, err := GenerateClientCSR("client_alice")
	if err != nil {
		t.Fatalf("GenerateClientCSR() error = %v", err)
	}
	if block, _ := pem.Decode(csr.PrivateKeyPEM); block == nil || block.Type != "PRIVATE KEY" {
		t.Fatalf("unexpected private key PEM block")
	}
	block, _ := pem.Decode(csr.CSRPem)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		t.Fatalf("unexpected CSR PEM block")
	}
	parsed, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificateRequest() error = %v", err)
	}
	if err := parsed.CheckSignature(); err != nil {
		t.Fatalf("CSR signature invalid: %v", err)
	}
	if parsed.Subject.CommonName != "client_alice" {
		t.Fatalf("CommonName = %q", parsed.Subject.CommonName)
	}
	if len(parsed.DNSNames) != 1 || parsed.DNSNames[0] != "client_alice" {
		t.Fatalf("DNSNames = %#v", parsed.DNSNames)
	}
}

func TestGenerateClientCSRRejectsInvalidClientID(t *testing.T) {
	_, err := GenerateClientCSR("client bad")
	if !errors.Is(err, ErrInvalidClientID) {
		t.Fatalf("GenerateClientCSR() error = %v, want %v", err, ErrInvalidClientID)
	}
}
