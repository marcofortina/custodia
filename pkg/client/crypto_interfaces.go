// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

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

// RecipientPublicKey is resolved by application trust logic.
// Server-published public-key metadata is discovery data, not a trust decision.
type RecipientPublicKey struct {
	ClientID    string
	Scheme      string
	PublicKey   []byte
	Fingerprint string
}

// PublicKeyResolver resolves recipient encryption keys from an application
// controlled source such as pinned files, KMS, directory services or config.
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

// CryptoOptions wires the high-level crypto client to local trust material.
// None of these providers are sent to the server; they only operate locally.
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
