package signing

import (
	"crypto"
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

func TestPKCS11CommandSigner(t *testing.T) {
	caCertPEM, _ := testCA(t)
	caCert, err := parseCertificatePEM(caCertPEM)
	if err != nil {
		t.Fatalf("parseCertificatePEM() error = %v", err)
	}
	provider := PKCS11CAKeyProvider{PublicKey: caCert.PublicKey, Command: `printf '{"signature":"c2lnbmF0dXJl"}'`}
	signer, err := provider.Signer()
	if err != nil {
		t.Fatalf("Signer() error = %v", err)
	}
	signature, err := signer.Sign(nil, []byte("digest"), crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if string(signature) != "signature" {
		t.Fatalf("signature = %q", string(signature))
	}
}

func TestLoadClientCertificateSignerWithPKCS11Command(t *testing.T) {
	caCertPEM, _ := testCA(t)
	certPath := t.TempDir() + "/ca.pem"
	if err := os.WriteFile(certPath, caCertPEM, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	signer, err := LoadClientCertificateSignerWithPKCS11Command(KeyProviderPKCS11, certPath, "", `printf '{"signature":"c2ln"}'`)
	if err != nil {
		t.Fatalf("LoadClientCertificateSignerWithPKCS11Command() error = %v", err)
	}
	if signer == nil {
		t.Fatal("expected signer")
	}
}

func TestPKCS11CommandSignerRejectsBadCommandResponse(t *testing.T) {
	caCertPEM, _ := testCA(t)
	caCert, err := parseCertificatePEM(caCertPEM)
	if err != nil {
		t.Fatalf("parseCertificatePEM() error = %v", err)
	}
	provider := PKCS11CAKeyProvider{PublicKey: caCert.PublicKey, Command: `printf '{"signature":"not-base64"}'`}
	signer, err := provider.Signer()
	if err != nil {
		t.Fatalf("Signer() error = %v", err)
	}
	_, err = signer.Sign(nil, []byte("digest"), crypto.SHA256)
	if !errors.Is(err, ErrPKCS11CommandFailed) {
		t.Fatalf("Sign() error = %v, want %v", err, ErrPKCS11CommandFailed)
	}
}
