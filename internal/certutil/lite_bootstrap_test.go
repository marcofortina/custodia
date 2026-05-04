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
	"strings"
	"testing"
	"time"
)

func TestGenerateLiteBootstrapCreatesExpectedArtifacts(t *testing.T) {
	artifacts, err := GenerateLiteBootstrap(LiteBootstrapRequest{AdminClientID: "admin", ServerName: "localhost", Passphrase: []byte("change-me"), Now: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)})
	if err != nil {
		t.Fatalf("GenerateLiteBootstrap() error = %v", err)
	}
	for name, payload := range map[string][]byte{
		"ca cert":     artifacts.CACertPEM,
		"ca key":      artifacts.CAKeyPEM,
		"server cert": artifacts.ServerCertPEM,
		"server key":  artifacts.ServerKeyPEM,
		"admin cert":  artifacts.AdminCertPEM,
		"admin key":   artifacts.AdminKeyPEM,
		"client crl":  artifacts.ClientCRLPEM,
		"config":      artifacts.ConfigYAML,
	} {
		if len(payload) == 0 {
			t.Fatalf("empty %s artifact", name)
		}
	}
	if !artifacts.PassphraseSet {
		t.Fatal("expected PassphraseSet")
	}
	block, _ := pem.Decode(artifacts.CAKeyPEM)
	if block == nil || !x509.IsEncryptedPEMBlock(block) {
		t.Fatalf("expected encrypted CA key PEM, got %v", block)
	}
	if !strings.Contains(string(artifacts.ConfigYAML), "profile: lite") || !strings.Contains(string(artifacts.ConfigYAML), "admin_client_ids: admin") {
		t.Fatalf("unexpected config yaml: %s", string(artifacts.ConfigYAML))
	}
}

func TestGenerateLiteBootstrapRejectsInvalidAdminClientID(t *testing.T) {
	_, err := GenerateLiteBootstrap(LiteBootstrapRequest{AdminClientID: "bad client"})
	if !errors.Is(err, ErrInvalidLiteBootstrapInput) {
		t.Fatalf("GenerateLiteBootstrap() error = %v, want %v", err, ErrInvalidLiteBootstrapInput)
	}
}

func TestGenerateLiteBootstrapServerIPGoesToIPAddresses(t *testing.T) {
	artifacts, err := GenerateLiteBootstrap(LiteBootstrapRequest{AdminClientID: "admin", ServerName: "127.0.0.1"})
	if err != nil {
		t.Fatalf("GenerateLiteBootstrap() error = %v", err)
	}
	cert := parseTestCertificate(t, artifacts.ServerCertPEM)
	if len(cert.IPAddresses) != 1 || cert.IPAddresses[0].String() != "127.0.0.1" {
		t.Fatalf("unexpected IP SANs: %#v", cert.IPAddresses)
	}
}

func parseTestCertificate(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("missing certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}
	return cert
}
