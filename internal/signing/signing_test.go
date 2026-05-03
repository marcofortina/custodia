package signing

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"
)

func TestClientCertificateSignerSignsClientAuthCertificate(t *testing.T) {
	caCertPEM, caKeyPEM := testCA(t)
	csrPEM := testCSR(t, "client_alice")
	signer, err := NewClientCertificateSigner(caCertPEM, caKeyPEM)
	if err != nil {
		t.Fatalf("NewClientCertificateSigner() error = %v", err)
	}
	issued, err := signer.SignClientCSR(csrPEM, "client_alice", time.Hour, time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))
	if err != nil {
		t.Fatalf("SignClientCSR() error = %v", err)
	}
	cert := parseIssuedCert(t, []byte(issued.CertificatePEM))
	if cert.Subject.CommonName != "client_alice" {
		t.Fatalf("CommonName = %q", cert.Subject.CommonName)
	}
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "client_alice" {
		t.Fatalf("DNSNames = %#v", cert.DNSNames)
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatalf("ExtKeyUsage = %#v", cert.ExtKeyUsage)
	}
	if issued.NotAfter.Sub(issued.NotBefore) < time.Hour {
		t.Fatalf("certificate validity too short: %s", issued.NotAfter.Sub(issued.NotBefore))
	}
}

func TestClientCertificateSignerRejectsCSRForDifferentClient(t *testing.T) {
	caCertPEM, caKeyPEM := testCA(t)
	signer, err := NewClientCertificateSigner(caCertPEM, caKeyPEM)
	if err != nil {
		t.Fatalf("NewClientCertificateSigner() error = %v", err)
	}
	_, err = signer.SignClientCSR(testCSR(t, "client_alice"), "client_bob", time.Hour, time.Now())
	if !errors.Is(err, ErrInvalidClientID) {
		t.Fatalf("SignClientCSR() error = %v, want %v", err, ErrInvalidClientID)
	}
}

func TestClientCertificateSignerRejectsInvalidTTL(t *testing.T) {
	caCertPEM, caKeyPEM := testCA(t)
	signer, err := NewClientCertificateSigner(caCertPEM, caKeyPEM)
	if err != nil {
		t.Fatalf("NewClientCertificateSigner() error = %v", err)
	}
	_, err = signer.SignClientCSR(testCSR(t, "client_alice"), "client_alice", MaxClientCertificateTTL+time.Hour, time.Now())
	if !errors.Is(err, ErrInvalidTTL) {
		t.Fatalf("SignClientCSR() error = %v, want %v", err, ErrInvalidTTL)
	}
}

func testCA(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "custodia-test-ca"},
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

func testCSR(t *testing.T, clientID string) []byte {
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

func parseIssuedCert(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("missing certificate PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}
	return cert
}
