package client

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

type fixedClock struct{}

func (fixedClock) Now() time.Time { return time.Unix(1, 0).UTC() }

type testResolver struct{}

func (testResolver) ResolveRecipientPublicKey(_ context.Context, clientID string) (RecipientPublicKey, error) {
	return RecipientPublicKey{ClientID: clientID, Scheme: CryptoEnvelopeHPKEV1, PublicKey: []byte("public")}, nil
}

type testPrivateKeyHandle struct{}

func (testPrivateKeyHandle) ClientID() string { return "client_alice" }
func (testPrivateKeyHandle) Scheme() string   { return CryptoEnvelopeHPKEV1 }
func (testPrivateKeyHandle) OpenEnvelope(_ context.Context, envelope []byte, _ []byte) ([]byte, error) {
	return envelope, nil
}

type testPrivateKeyProvider struct{}

func (testPrivateKeyProvider) CurrentPrivateKey(context.Context) (PrivateKeyHandle, error) {
	return testPrivateKeyHandle{}, nil
}

func TestCryptoOptionsValidate(t *testing.T) {
	opts := CryptoOptions{
		PublicKeyResolver:  testResolver{},
		PrivateKeyProvider: testPrivateKeyProvider{},
		RandomSource:       bytes.NewReader([]byte("random")),
		Clock:              fixedClock{},
	}
	if err := opts.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestCryptoOptionsValidateRequiresDependencies(t *testing.T) {
	cases := []struct {
		name string
		opts CryptoOptions
		want error
	}{
		{name: "resolver", opts: CryptoOptions{}, want: ErrMissingPublicKeyResolver},
		{name: "provider", opts: CryptoOptions{PublicKeyResolver: testResolver{}}, want: ErrMissingPrivateKeyProvider},
		{name: "random", opts: CryptoOptions{PublicKeyResolver: testResolver{}, PrivateKeyProvider: testPrivateKeyProvider{}}, want: ErrMissingRandomSource},
		{name: "clock", opts: CryptoOptions{PublicKeyResolver: testResolver{}, PrivateKeyProvider: testPrivateKeyProvider{}, RandomSource: bytes.NewReader(nil)}, want: ErrMissingClock},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.opts.Validate(); !errors.Is(err, tc.want) {
				t.Fatalf("Validate() error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestSystemClockReturnsUTC(t *testing.T) {
	if got := (SystemClock{}).Now().Location(); got != time.UTC {
		t.Fatalf("SystemClock location = %v, want UTC", got)
	}
}
