package client

import (
	"context"
	"errors"
	"io"
	"time"
)

const (
	CryptoVersionV1       = "custodia.client-crypto.v1"
	CryptoContentCipherV1 = "aes-256-gcm"
	CryptoEnvelopeHPKEV1  = "hpke-v1"
)

var (
	ErrMissingPublicKeyResolver  = errors.New("missing public key resolver")
	ErrMissingPrivateKeyProvider = errors.New("missing private key provider")
	ErrMissingRandomSource       = errors.New("missing random source")
	ErrMissingClock              = errors.New("missing clock")
	ErrMissingRecipientEnvelope  = errors.New("missing recipient envelope")
	ErrWrongRecipient            = errors.New("wrong recipient")
	ErrAADMismatch               = errors.New("aad mismatch")
	ErrCiphertextAuthFailed      = errors.New("ciphertext authentication failed")
	ErrUnsupportedCryptoVersion  = errors.New("unsupported crypto version")
	ErrUnsupportedContentCipher  = errors.New("unsupported content cipher")
	ErrUnsupportedEnvelopeScheme = errors.New("unsupported envelope scheme")
	ErrMalformedCryptoMetadata   = errors.New("malformed crypto metadata")
	ErrRandomSourceFailed        = errors.New("random source failed")
)

type RecipientPublicKey struct {
	ClientID    string
	Scheme      string
	PublicKey   []byte
	Fingerprint string
}

type PublicKeyResolver interface {
	ResolveRecipientPublicKey(ctx context.Context, clientID string) (RecipientPublicKey, error)
}

type PrivateKeyHandle interface {
	ClientID() string
	Scheme() string
	OpenEnvelope(ctx context.Context, envelope []byte, aad []byte) ([]byte, error)
}

type PrivateKeyProvider interface {
	CurrentPrivateKey(ctx context.Context) (PrivateKeyHandle, error)
}

type Clock interface {
	Now() time.Time
}

type CryptoOptions struct {
	PublicKeyResolver  PublicKeyResolver
	PrivateKeyProvider PrivateKeyProvider
	RandomSource       io.Reader
	Clock              Clock
}

func (opts CryptoOptions) Validate() error {
	if opts.PublicKeyResolver == nil {
		return ErrMissingPublicKeyResolver
	}
	if opts.PrivateKeyProvider == nil {
		return ErrMissingPrivateKeyProvider
	}
	if opts.RandomSource == nil {
		return ErrMissingRandomSource
	}
	if opts.Clock == nil {
		return ErrMissingClock
	}
	return nil
}

type SystemClock struct{}

func (SystemClock) Now() time.Time {
	return time.Now().UTC()
}
