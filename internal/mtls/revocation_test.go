package mtls

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadRevokedClientSerialsRejectsRevokedCertificate(t *testing.T) {
	caCert, caKey := testCertificateAuthority(t)
	clientCert := testClientCertificate(t, caCert, caKey, big.NewInt(42))
	crlPEM := testRevocationList(t, caCert, caKey, clientCert.SerialNumber)

	crlFile := filepath.Join(t.TempDir(), "clients.crl.pem")
	if err := os.WriteFile(crlFile, crlPEM, 0o600); err != nil {
		t.Fatalf("write CRL: %v", err)
	}

	revoked, err := LoadRevokedClientSerials(crlFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw}))
	if err != nil {
		t.Fatalf("load revoked serials: %v", err)
	}

	err = revokedClientVerifier(revoked)([][]byte{clientCert.Raw}, nil)
	if !errors.Is(err, ErrRevokedClientCertificate) {
		t.Fatalf("expected revoked certificate error, got %v", err)
	}
}

func TestLoadRevokedClientSerialsRequiresTrustedCRLSignature(t *testing.T) {
	caCert, _ := testCertificateAuthority(t)
	otherCert, otherKey := testCertificateAuthority(t)
	crlPEM := testRevocationList(t, otherCert, otherKey, big.NewInt(7))

	crlFile := filepath.Join(t.TempDir(), "untrusted.crl.pem")
	if err := os.WriteFile(crlFile, crlPEM, 0o600); err != nil {
		t.Fatalf("write CRL: %v", err)
	}

	_, err := LoadRevokedClientSerials(crlFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw}))
	if err == nil {
		t.Fatal("expected untrusted CRL signature error")
	}
}

func testCertificateAuthority(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(now.UnixNano()),
		Subject:               pkix.Name{CommonName: "Custodia test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA certificate: %v", err)
	}
	return cert, key
}

func testClientCertificate(t *testing.T, caCert *x509.Certificate, caKey *rsa.PrivateKey, serial *big.Int) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "client_alice"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create client certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse client certificate: %v", err)
	}
	return cert
}

func testRevocationList(t *testing.T, caCert *x509.Certificate, caKey *rsa.PrivateKey, serial *big.Int) []byte {
	t.Helper()
	now := time.Now().UTC()
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		SignatureAlgorithm: x509.SHA256WithRSA,
		Number:             big.NewInt(now.UnixNano()),
		ThisUpdate:         now.Add(-time.Minute),
		NextUpdate:         now.Add(time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{{
			SerialNumber:   serial,
			RevocationTime: now,
		}},
	}, caCert, caKey)
	if err != nil {
		t.Fatalf("create CRL: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})
}

func TestReloadableCRLVerifierReloadsChangedRevocationList(t *testing.T) {
	caCert, caKey := testCertificateAuthority(t)
	clientCert := testClientCertificate(t, caCert, caKey, big.NewInt(99))
	crlFile := filepath.Join(t.TempDir(), "clients.crl.pem")
	if err := os.WriteFile(crlFile, testRevocationListWithoutEntries(t, caCert, caKey), 0o600); err != nil {
		t.Fatalf("write initial CRL: %v", err)
	}

	verifier, err := newReloadableCRLVerifier(crlFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw}))
	if err != nil {
		t.Fatalf("create reloadable verifier: %v", err)
	}
	if err := verifier.Verify([][]byte{clientCert.Raw}, nil); err != nil {
		t.Fatalf("expected client certificate to be allowed before CRL update: %v", err)
	}

	if err := os.WriteFile(crlFile, testRevocationList(t, caCert, caKey, clientCert.SerialNumber), 0o600); err != nil {
		t.Fatalf("write updated CRL: %v", err)
	}
	future := time.Now().Add(time.Second).UTC()
	if err := os.Chtimes(crlFile, future, future); err != nil {
		t.Fatalf("touch updated CRL: %v", err)
	}

	err = verifier.Verify([][]byte{clientCert.Raw}, nil)
	if !errors.Is(err, ErrRevokedClientCertificate) {
		t.Fatalf("expected revoked certificate after CRL reload, got %v", err)
	}
}

func testRevocationListWithoutEntries(t *testing.T, caCert *x509.Certificate, caKey *rsa.PrivateKey) []byte {
	t.Helper()
	now := time.Now().UTC()
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		SignatureAlgorithm: x509.SHA256WithRSA,
		Number:             big.NewInt(now.UnixNano()),
		ThisUpdate:         now.Add(-time.Minute),
		NextUpdate:         now.Add(time.Hour),
	}, caCert, caKey)
	if err != nil {
		t.Fatalf("create CRL: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})
}
