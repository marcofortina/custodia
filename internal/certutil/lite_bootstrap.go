// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package certutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"strings"
	"time"

	"custodia/internal/model"
)

var ErrInvalidLiteBootstrapInput = errors.New("invalid lite bootstrap input")

type LiteBootstrapRequest struct {
	AdminClientID string
	ServerName    string
	Passphrase    []byte
	Now           time.Time
}

// LiteBootstrapArtifacts are generated for single-node bootstrap and should be moved into restricted paths immediately.
type LiteBootstrapArtifacts struct {
	CACertPEM        []byte
	CAKeyPEM         []byte
	ServerCertPEM    []byte
	ServerKeyPEM     []byte
	AdminCertPEM     []byte
	AdminKeyPEM      []byte
	ClientCRLPEM     []byte
	ConfigYAML       []byte
	SignerConfigYAML []byte
	PassphraseSet    bool
}

// GenerateLiteBootstrap creates a local CA, server certificate, admin client certificate and empty CRL for first-run Lite installs.
func GenerateLiteBootstrap(req LiteBootstrapRequest) (*LiteBootstrapArtifacts, error) {
	adminClientID := strings.TrimSpace(req.AdminClientID)
	if !model.ValidClientID(adminClientID) {
		return nil, ErrInvalidLiteBootstrapInput
	}
	serverName := strings.TrimSpace(req.ServerName)
	if serverName == "" {
		serverName = "localhost"
	}
	now := req.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	caCert, caCertPEM, err := createLiteCA(now, caKey)
	if err != nil {
		return nil, err
	}
	caKeyPEM, err := encodePrivateKey(caKey, req.Passphrase)
	if err != nil {
		return nil, err
	}
	serverCertPEM, serverKeyPEM, err := createLiteLeaf(now, caCert, caKey, serverName, x509.ExtKeyUsageServerAuth)
	if err != nil {
		return nil, err
	}
	adminCertPEM, adminKeyPEM, err := createLiteLeaf(now, caCert, caKey, adminClientID, x509.ExtKeyUsageClientAuth)
	if err != nil {
		return nil, err
	}
	crlPEM, err := createEmptyCRL(now, caCert, caKey)
	if err != nil {
		return nil, err
	}
	return &LiteBootstrapArtifacts{
		CACertPEM:        caCertPEM,
		CAKeyPEM:         caKeyPEM,
		ServerCertPEM:    serverCertPEM,
		ServerKeyPEM:     serverKeyPEM,
		AdminCertPEM:     adminCertPEM,
		AdminKeyPEM:      adminKeyPEM,
		ClientCRLPEM:     crlPEM,
		ConfigYAML:       liteBootstrapConfigYAML(adminClientID),
		SignerConfigYAML: liteBootstrapSignerConfigYAML(adminClientID),
		PassphraseSet:    len(req.Passphrase) > 0,
	}, nil
}

func createLiteCA(now time.Time, key *ecdsa.PrivateKey) (*x509.Certificate, []byte, error) {
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "custodia-lite-local-ca"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(3650 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

func createLiteLeaf(now time.Time, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, name string, usage x509.ExtKeyUsage) ([]byte, []byte, error) {
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(825 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
	}
	if usage == x509.ExtKeyUsageServerAuth {
		if ip := net.ParseIP(name); ip != nil {
			tmpl.IPAddresses = []net.IP{ip}
		} else {
			tmpl.DNSNames = []string{name}
		}
	} else {
		tmpl.DNSNames = []string{name}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err := encodePrivateKey(leafKey, nil)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), keyPEM, nil
}

func createEmptyCRL(now time.Time, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) ([]byte, error) {
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     serial,
		ThisUpdate: now.Add(-time.Minute),
		NextUpdate: now.Add(24 * time.Hour),
	}, caCert, caKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}), nil
}

func encodePrivateKey(key *ecdsa.PrivateKey, passphrase []byte) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	if len(passphrase) > 0 {
		block, err := x509.EncryptPEMBlock(rand.Reader, "ENCRYPTED PRIVATE KEY", der, passphrase, x509.PEMCipherAES256)
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(block), nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func randomSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

func liteBootstrapConfigYAML(adminClientID string) []byte {
	return []byte(`profile: lite
api_addr: ":8443"
web_addr: ":9443"
log_file: /var/log/custodia/custodia.log
store_backend: sqlite
database_url: file:/var/lib/custodia/custodia.db
rate_limit_backend: memory
deployment_mode: lite-single-node
database_ha_target: none
web_mfa_required: true
web_passkey_enabled: false
client_ca_file: /etc/custodia/client-ca.crt
client_crl_file: /etc/custodia/client.crl.pem
tls_cert_file: /etc/custodia/server.crt
tls_key_file: /etc/custodia/server.key
signer_key_provider: file
signer_ca_cert_file: /etc/custodia/ca.crt
signer_ca_key_file: /etc/custodia/ca.key
signer_ca_key_passphrase_file: /etc/custodia/ca.pass
bootstrap_clients:
  - client_id: ` + adminClientID + `
    mtls_subject: ` + adminClientID + `
admin_client_ids:
  - ` + adminClientID + `
`)
}

func liteBootstrapSignerConfigYAML(adminClientID string) []byte {
	return []byte(`addr: ":9444"
tls_cert_file: /etc/custodia/server.crt
tls_key_file: /etc/custodia/server.key
client_ca_file: /etc/custodia/client-ca.crt
admin_subjects:
  - ` + adminClientID + `
key_provider: file
ca_cert_file: /etc/custodia/ca.crt
ca_key_file: /etc/custodia/ca.key
ca_key_passphrase_file: /etc/custodia/ca.pass
crl_file: /etc/custodia/client.crl.pem
audit_log_file: /var/log/custodia/signer-audit.jsonl
shutdown_timeout_seconds: 10
`)
}
