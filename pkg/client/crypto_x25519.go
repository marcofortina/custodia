// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package client

import (
	"context"
	"fmt"

	"custodia/internal/clientcrypto"
)

type X25519PrivateKeyHandle struct {
	clientID   string
	privateKey []byte
}

func NewX25519PrivateKeyHandle(clientID string, privateKey []byte) (X25519PrivateKeyHandle, error) {
	if _, err := clientcrypto.DeriveX25519PublicKey(privateKey); err != nil {
		return X25519PrivateKeyHandle{}, mapClientCryptoError(err)
	}
	return X25519PrivateKeyHandle{clientID: clientID, privateKey: append([]byte{}, privateKey...)}, nil
}

func DeriveX25519RecipientPublicKey(clientID string, privateKey []byte) (RecipientPublicKey, error) {
	publicKey, err := clientcrypto.DeriveX25519PublicKey(privateKey)
	if err != nil {
		return RecipientPublicKey{}, mapClientCryptoError(err)
	}
	return RecipientPublicKey{ClientID: clientID, Scheme: CryptoEnvelopeHPKEV1, PublicKey: publicKey}, nil
}

func (handle X25519PrivateKeyHandle) ClientID() string { return handle.clientID }

func (X25519PrivateKeyHandle) Scheme() string { return CryptoEnvelopeHPKEV1 }

func (handle X25519PrivateKeyHandle) OpenEnvelope(_ context.Context, envelope []byte, aad []byte) ([]byte, error) {
	dek, err := clientcrypto.OpenHPKEV1Envelope(handle.privateKey, envelope, aad)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrWrongRecipient, mapClientCryptoError(err))
	}
	return dek, nil
}
