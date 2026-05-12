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
	"net"
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
		"ca cert":       artifacts.CACertPEM,
		"ca key":        artifacts.CAKeyPEM,
		"server cert":   artifacts.ServerCertPEM,
		"server key":    artifacts.ServerKeyPEM,
		"admin cert":    artifacts.AdminCertPEM,
		"admin key":     artifacts.AdminKeyPEM,
		"client crl":    artifacts.ClientCRLPEM,
		"server config": artifacts.ConfigYAML,
		"signer config": artifacts.SignerConfigYAML,
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
	configYAML := string(artifacts.ConfigYAML)
	for _, expected := range []string{"profile: lite", "server:", "storage:", "tls:", "signer:", "bootstrap_clients:", "client_id: admin", "mtls_subject: admin", "admin_client_ids:", "- admin"} {
		if !strings.Contains(configYAML, expected) {
			t.Fatalf("expected config yaml to contain %q: %s", expected, configYAML)
		}
	}
	signerConfigYAML := string(artifacts.SignerConfigYAML)
	for _, expected := range []string{`server:`, `addr: ":9444"`, "admin:", "subjects:", "- admin", "ca:", "key_passphrase_file: /etc/custodia/ca.pass"} {
		if !strings.Contains(signerConfigYAML, expected) {
			t.Fatalf("expected signer config yaml to contain %q: %s", expected, signerConfigYAML)
		}
	}
}

func TestGenerateLiteBootstrapRejectsInvalidAdminClientID(t *testing.T) {
	_, err := GenerateLiteBootstrap(LiteBootstrapRequest{AdminClientID: "bad client"})
	if !errors.Is(err, ErrInvalidLiteBootstrapInput) {
		t.Fatalf("GenerateLiteBootstrap() error = %v, want %v", err, ErrInvalidLiteBootstrapInput)
	}
}

func TestGenerateLiteBootstrapServerIPAddsLocalhostSANs(t *testing.T) {
	artifacts, err := GenerateLiteBootstrap(LiteBootstrapRequest{AdminClientID: "admin", ServerName: "192.0.2.10"})
	if err != nil {
		t.Fatalf("GenerateLiteBootstrap() error = %v", err)
	}
	cert := parseTestCertificate(t, artifacts.ServerCertPEM)
	assertTestDNSName(t, cert, "localhost")
	assertTestIPAddress(t, cert, "192.0.2.10")
	assertTestIPAddress(t, cert, "127.0.0.1")
	assertTestIPAddress(t, cert, "::1")
}

func TestLiteServerSANsAddsResolvedNonLoopbackIP(t *testing.T) {
	dnsNames, ipAddresses := liteServerSANs("custodia.example.internal", nil, func(name string) ([]net.IP, error) {
		if name != "custodia.example.internal" {
			t.Fatalf("unexpected lookup name %q", name)
		}
		return []net.IP{net.ParseIP("192.0.2.10"), net.ParseIP("127.0.1.1")}, nil
	})
	if !containsString(dnsNames, "custodia.example.internal") || !containsString(dnsNames, "localhost") {
		t.Fatalf("unexpected DNS SANs: %#v", dnsNames)
	}
	if !containsIPString(ipAddresses, "192.0.2.10") || !containsIPString(ipAddresses, "127.0.0.1") || !containsIPString(ipAddresses, "::1") {
		t.Fatalf("unexpected IP SANs: %#v", ipAddresses)
	}
	if containsIPString(ipAddresses, "127.0.1.1") {
		t.Fatalf("resolved loopback should not be added automatically: %#v", ipAddresses)
	}
}

func TestGenerateLiteBootstrapAddsAdditionalServerSANs(t *testing.T) {
	artifacts, err := GenerateLiteBootstrap(LiteBootstrapRequest{AdminClientID: "admin", ServerName: "custodia.example.internal", AdditionalServerSANs: []string{"custodia-custodia-signer", "custodia-custodia-signer.custodia.svc", "192.0.2.20"}})
	if err != nil {
		t.Fatalf("GenerateLiteBootstrap() error = %v", err)
	}
	cert := parseTestCertificate(t, artifacts.ServerCertPEM)
	assertTestDNSName(t, cert, "custodia.example.internal")
	assertTestDNSName(t, cert, "custodia-custodia-signer")
	assertTestDNSName(t, cert, "custodia-custodia-signer.custodia.svc")
	assertTestIPAddress(t, cert, "192.0.2.20")
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

func assertTestDNSName(t *testing.T, cert *x509.Certificate, name string) {
	t.Helper()
	if !containsString(cert.DNSNames, name) {
		t.Fatalf("expected DNS SAN %q in %#v", name, cert.DNSNames)
	}
}

func assertTestIPAddress(t *testing.T, cert *x509.Certificate, want string) {
	t.Helper()
	if !containsIPString(cert.IPAddresses, want) {
		t.Fatalf("expected IP SAN %q in %#v", want, cert.IPAddresses)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func containsIPString(values []net.IP, want string) bool {
	for _, value := range values {
		if value.String() == want {
			return true
		}
	}
	return false
}
