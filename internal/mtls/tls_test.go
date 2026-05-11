// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package mtls

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestServerTLSConfigAllowsEnrollmentBeforeClientCertificate(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey := testCertificateAuthority(t)
	serverCert, serverKey := testTLSServerCertificate(t, caCert, caKey, "custodia")
	serverCertFile := filepath.Join(dir, "server.crt")
	serverKeyFile := filepath.Join(dir, "server.key")
	clientCAFile := filepath.Join(dir, "client-ca.crt")
	writeTLSTestPEMFile(t, serverCertFile, "CERTIFICATE", serverCert.Raw)
	writeTLSTestPEMFile(t, serverKeyFile, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(serverKey))
	writeTLSTestPEMFile(t, clientCAFile, "CERTIFICATE", caCert.Raw)

	cfg, err := ServerTLSConfig(serverCertFile, serverKeyFile, clientCAFile)
	if err != nil {
		t.Fatalf("ServerTLSConfig() error = %v", err)
	}
	if cfg.ClientAuth != tls.VerifyClientCertIfGiven {
		t.Fatalf("ClientAuth = %v, want VerifyClientCertIfGiven", cfg.ClientAuth)
	}
	if len(cfg.ClientCAs.Subjects()) == 0 {
		t.Fatalf("expected client CA pool to be configured")
	}
}

func testTLSServerCertificate(t *testing.T, caCert *x509.Certificate, caKey *rsa.PrivateKey, commonName string) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject:      pkix.Name{CommonName: commonName},
		DNSNames:     []string{commonName},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create server certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse server certificate: %v", err)
	}
	return cert, key
}

func writeTLSTestPEMFile(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	data := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	if data == nil {
		t.Fatalf("encode PEM block %s", blockType)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
