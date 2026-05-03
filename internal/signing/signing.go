package signing

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"time"

	"custodia/internal/model"
)

const (
	DefaultClientCertificateTTL = 24 * time.Hour
	MaxClientCertificateTTL     = 90 * 24 * time.Hour
)

var (
	ErrInvalidCSR      = errors.New("invalid certificate signing request")
	ErrInvalidCA       = errors.New("invalid certificate authority material")
	ErrInvalidClientID = errors.New("invalid certificate client id")
	ErrInvalidTTL      = errors.New("invalid certificate ttl")
)

type SignClientCertificateRequest struct {
	ClientID string `json:"client_id"`
	CSRPem   string `json:"csr_pem"`
	TTLHours int    `json:"ttl_hours,omitempty"`
}

type SignClientCertificateResponse struct {
	ClientID       string    `json:"client_id"`
	CertificatePEM string    `json:"certificate_pem"`
	NotBefore      time.Time `json:"not_before"`
	NotAfter       time.Time `json:"not_after"`
}

type ClientCertificateSigner struct {
	caCert *x509.Certificate
	caKey  crypto.Signer
}

func NewClientCertificateSigner(caCertPEM, caKeyPEM []byte) (*ClientCertificateSigner, error) {
	caCert, err := parseCertificatePEM(caCertPEM)
	if err != nil {
		return nil, err
	}
	if !caCert.IsCA {
		return nil, ErrInvalidCA
	}
	caKey, err := parseSignerPEM(caKeyPEM)
	if err != nil {
		return nil, err
	}
	return &ClientCertificateSigner{caCert: caCert, caKey: caKey}, nil
}

func (s *ClientCertificateSigner) SignClientCSR(csrPEM []byte, clientID string, ttl time.Duration, now time.Time) (*SignClientCertificateResponse, error) {
	clientID = strings.TrimSpace(clientID)
	if !model.ValidClientID(clientID) {
		return nil, ErrInvalidClientID
	}
	if ttl <= 0 || ttl > MaxClientCertificateTTL {
		return nil, ErrInvalidTTL
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	csr, err := parseCSRPEM(csrPEM)
	if err != nil {
		return nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, ErrInvalidCSR
	}
	if !csrContainsClientID(csr, clientID) {
		return nil, ErrInvalidClientID
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	notBefore := now.UTC().Add(-time.Minute)
	notAfter := now.UTC().Add(ttl)
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: clientID},
		DNSNames:              []string{clientID},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, s.caCert, csr.PublicKey, s.caKey)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	return &SignClientCertificateResponse{
		ClientID:       clientID,
		CertificatePEM: string(certPEM),
		NotBefore:      notBefore,
		NotAfter:       notAfter,
	}, nil
}

func parseCertificatePEM(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, ErrInvalidCA
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, ErrInvalidCA
	}
	return cert, nil
}

func parseCSRPEM(data []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, ErrInvalidCSR
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, ErrInvalidCSR
	}
	return csr, nil
}

func parseSignerPEM(data []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, ErrInvalidCA
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return signerFromPrivateKey(key)
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, ErrInvalidCA
}

func signerFromPrivateKey(key any) (crypto.Signer, error) {
	switch typed := key.(type) {
	case *rsa.PrivateKey:
		return typed, nil
	case *ecdsa.PrivateKey:
		return typed, nil
	case ed25519.PrivateKey:
		return typed, nil
	default:
		return nil, ErrInvalidCA
	}
}

func csrContainsClientID(csr *x509.CertificateRequest, clientID string) bool {
	if strings.TrimSpace(csr.Subject.CommonName) == clientID {
		return true
	}
	for _, dns := range csr.DNSNames {
		if strings.TrimSpace(dns) == clientID {
			return true
		}
	}
	for _, uri := range csr.URIs {
		if uri != nil && strings.TrimSpace(uri.String()) == clientID {
			return true
		}
	}
	return false
}

func randomSerial() (*big.Int, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	if serial.Sign() == 0 {
		return randomSerial()
	}
	return serial, nil
}
