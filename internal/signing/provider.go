package signing

import (
	"crypto"
	"errors"
	"fmt"
	"os"
	"strings"
)

const (
	KeyProviderFile   = "file"
	KeyProviderPKCS11 = "pkcs11"
)

var (
	ErrUnsupportedKeyProvider = errors.New("unsupported signing key provider")
	ErrPKCS11NotImplemented   = errors.New("pkcs11 signing key provider is not implemented in this build")
)

type CAKeyProvider interface {
	Signer() (crypto.Signer, error)
}

type FileCAKeyProvider struct {
	KeyPEM []byte
}

func (p FileCAKeyProvider) Signer() (crypto.Signer, error) {
	return parseSignerPEM(p.KeyPEM)
}

type PKCS11CAKeyProvider struct{}

func (PKCS11CAKeyProvider) Signer() (crypto.Signer, error) {
	return nil, ErrPKCS11NotImplemented
}

func NewClientCertificateSignerWithKeyProvider(caCertPEM []byte, provider CAKeyProvider) (*ClientCertificateSigner, error) {
	caCert, err := parseCertificatePEM(caCertPEM)
	if err != nil {
		return nil, err
	}
	if !caCert.IsCA {
		return nil, ErrInvalidCA
	}
	if provider == nil {
		return nil, ErrInvalidCA
	}
	caKey, err := provider.Signer()
	if err != nil {
		return nil, err
	}
	return &ClientCertificateSigner{caCert: caCert, caKey: caKey}, nil
}

func LoadClientCertificateSigner(providerName, caCertFile, caKeyFile string) (*ClientCertificateSigner, error) {
	caCertPEM, err := os.ReadFile(strings.TrimSpace(caCertFile))
	if err != nil {
		return nil, fmt.Errorf("read CA certificate: %w", err)
	}
	switch normalizedKeyProvider(providerName) {
	case KeyProviderFile:
		caKeyPEM, err := os.ReadFile(strings.TrimSpace(caKeyFile))
		if err != nil {
			return nil, fmt.Errorf("read CA key: %w", err)
		}
		return NewClientCertificateSignerWithKeyProvider(caCertPEM, FileCAKeyProvider{KeyPEM: caKeyPEM})
	case KeyProviderPKCS11:
		return NewClientCertificateSignerWithKeyProvider(caCertPEM, PKCS11CAKeyProvider{})
	default:
		return nil, ErrUnsupportedKeyProvider
	}
}

func normalizedKeyProvider(providerName string) string {
	providerName = strings.ToLower(strings.TrimSpace(providerName))
	if providerName == "" {
		return KeyProviderFile
	}
	return providerName
}
