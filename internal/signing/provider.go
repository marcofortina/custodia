// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

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

// CAKeyProvider abstracts certificate signing material so Lite file keys and production command/HSM bridges share one signer path.
type CAKeyProvider interface {
	Signer() (crypto.Signer, error)
}

type FileCAKeyProvider struct {
	KeyPEM     []byte
	Passphrase []byte
}

func (p FileCAKeyProvider) Signer() (crypto.Signer, error) {
	return parseSignerPEMWithPassphrase(p.KeyPEM, p.Passphrase)
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

// Sign sends only the digest and hash name to the external signer command; private CA key material never returns to Custodia.
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
	return LoadClientCertificateSignerWithOptions(providerName, caCertFile, caKeyFile, os.Getenv("CUSTODIA_SIGNER_PKCS11_SIGN_COMMAND"), os.Getenv("CUSTODIA_SIGNER_CA_KEY_PASSPHRASE_FILE"))
}

func LoadClientCertificateSignerWithPKCS11Command(providerName, caCertFile, caKeyFile, pkcs11SignCommand string) (*ClientCertificateSigner, error) {
	return LoadClientCertificateSignerWithOptions(providerName, caCertFile, caKeyFile, pkcs11SignCommand, "")
}

func LoadClientCertificateSignerWithOptions(providerName, caCertFile, caKeyFile, pkcs11SignCommand, passphraseFile string) (*ClientCertificateSigner, error) {
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
		passphrase, err := readPassphraseFile(passphraseFile)
		if err != nil {
			return nil, err
		}
		return NewClientCertificateSignerWithKeyProvider(caCertPEM, FileCAKeyProvider{KeyPEM: caKeyPEM, Passphrase: passphrase})
	case KeyProviderPKCS11:
		return NewClientCertificateSignerWithKeyProvider(caCertPEM, PKCS11CAKeyProvider{PublicKey: caCert.PublicKey, Command: pkcs11SignCommand})
	default:
		return nil, ErrUnsupportedKeyProvider
	}
}

func readPassphraseFile(path string) ([]byte, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, nil
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read CA key passphrase: %w", err)
	}
	return []byte(strings.TrimSpace(string(payload))), nil
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
