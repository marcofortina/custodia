package signing

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

const (
	KeyProviderFile   = "file"
	KeyProviderPKCS11 = "pkcs11"
)

var (
	ErrUnsupportedKeyProvider = errors.New("unsupported signing key provider")
	ErrPKCS11NotImplemented   = errors.New("pkcs11 signing key provider is not implemented in this build")
	ErrPKCS11CommandFailed    = errors.New("pkcs11 signing command failed")
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

type PKCS11CAKeyProvider struct {
	PublicKey crypto.PublicKey
	Command   string
}

func (p PKCS11CAKeyProvider) Signer() (crypto.Signer, error) {
	command := strings.TrimSpace(p.Command)
	if command == "" {
		return nil, ErrPKCS11NotImplemented
	}
	if p.PublicKey == nil {
		return nil, ErrInvalidCA
	}
	return PKCS11CommandSigner{PublicKeyValue: p.PublicKey, Command: command}, nil
}

type PKCS11CommandSigner struct {
	PublicKeyValue crypto.PublicKey
	Command        string
}

func (s PKCS11CommandSigner) Public() crypto.PublicKey {
	return s.PublicKeyValue
}

func (s PKCS11CommandSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	request := pkcs11SignRequest{
		Digest: base64.StdEncoding.EncodeToString(digest),
		Hash:   hashName(opts),
	}
	stdin, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command("/bin/sh", "-c", s.Command)
	cmd.Stdin = bytes.NewReader(stdin)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%w: %v: %s", ErrPKCS11CommandFailed, err, strings.TrimSpace(stderr.String()))
	}
	var response pkcs11SignResponse
	if err := json.Unmarshal(stdout.Bytes(), &response); err != nil {
		return nil, fmt.Errorf("%w: invalid response: %v", ErrPKCS11CommandFailed, err)
	}
	signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(response.Signature))
	if err != nil || len(signature) == 0 {
		return nil, fmt.Errorf("%w: invalid signature", ErrPKCS11CommandFailed)
	}
	return signature, nil
}

type pkcs11SignRequest struct {
	Digest string `json:"digest"`
	Hash   string `json:"hash"`
}

type pkcs11SignResponse struct {
	Signature string `json:"signature"`
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
	return LoadClientCertificateSignerWithPKCS11Command(providerName, caCertFile, caKeyFile, os.Getenv("CUSTODIA_SIGNER_PKCS11_SIGN_COMMAND"))
}

func LoadClientCertificateSignerWithPKCS11Command(providerName, caCertFile, caKeyFile, pkcs11SignCommand string) (*ClientCertificateSigner, error) {
	caCertPEM, err := os.ReadFile(strings.TrimSpace(caCertFile))
	if err != nil {
		return nil, fmt.Errorf("read CA certificate: %w", err)
	}
	caCert, err := parseCertificatePEM(caCertPEM)
	if err != nil {
		return nil, err
	}
	switch normalizedKeyProvider(providerName) {
	case KeyProviderFile:
		caKeyPEM, err := os.ReadFile(strings.TrimSpace(caKeyFile))
		if err != nil {
			return nil, fmt.Errorf("read CA key: %w", err)
		}
		return NewClientCertificateSignerWithKeyProvider(caCertPEM, FileCAKeyProvider{KeyPEM: caKeyPEM})
	case KeyProviderPKCS11:
		return NewClientCertificateSignerWithKeyProvider(caCertPEM, PKCS11CAKeyProvider{PublicKey: caCert.PublicKey, Command: pkcs11SignCommand})
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

func hashName(opts crypto.SignerOpts) string {
	if opts == nil || opts.HashFunc() == 0 {
		return "none"
	}
	return opts.HashFunc().String()
}
