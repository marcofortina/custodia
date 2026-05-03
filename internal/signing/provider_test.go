package signing

import (
	"errors"
	"os"
	"testing"
)

func TestClientCertificateSignerWithFileKeyProvider(t *testing.T) {
	caCertPEM, caKeyPEM := testCA(t)
	signer, err := NewClientCertificateSignerWithKeyProvider(caCertPEM, FileCAKeyProvider{KeyPEM: caKeyPEM})
	if err != nil {
		t.Fatalf("NewClientCertificateSignerWithKeyProvider() error = %v", err)
	}
	if signer == nil {
		t.Fatal("expected signer")
	}
}

func TestLoadClientCertificateSignerRejectsPKCS11InThisBuild(t *testing.T) {
	caCertPEM, _ := testCA(t)
	certPath := t.TempDir() + "/ca.pem"
	if err := os.WriteFile(certPath, caCertPEM, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	_, err := LoadClientCertificateSigner(KeyProviderPKCS11, certPath, "")
	if !errors.Is(err, ErrPKCS11NotImplemented) {
		t.Fatalf("LoadClientCertificateSigner() error = %v, want %v", err, ErrPKCS11NotImplemented)
	}
}

func TestLoadClientCertificateSignerRejectsUnknownProvider(t *testing.T) {
	caCertPEM, _ := testCA(t)
	certPath := t.TempDir() + "/ca.pem"
	if err := os.WriteFile(certPath, caCertPEM, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	_, err := LoadClientCertificateSigner("cloudkms", certPath, "")
	if !errors.Is(err, ErrUnsupportedKeyProvider) {
		t.Fatalf("LoadClientCertificateSigner() error = %v, want %v", err, ErrUnsupportedKeyProvider)
	}
}
