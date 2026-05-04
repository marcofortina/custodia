// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package clientcrypto

// Content encryption helpers are deliberately small wrappers around AES-GCM.
// Nonce generation is left to SDK callers so deterministic vectors can pin the
// exact key/nonce/AAD tuple used across languages.

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

const (
	AES256GCMKeyBytes = 32
	AESGCMNonceBytes  = 12
	AESGCMTagBytes    = 16
)

var (
	ErrInvalidContentKey   = errors.New("invalid client content encryption key")
	ErrInvalidContentNonce = errors.New("invalid client content nonce")
	ErrContentAuthFailed   = errors.New("client content authentication failed")
)

// SealContentAES256GCM seals plaintext with AES-256-GCM and caller-provided AAD.
func SealContentAES256GCM(key, nonce, plaintext, aad []byte) ([]byte, error) {
	if len(key) != AES256GCMKeyBytes {
		return nil, ErrInvalidContentKey
	}
	if len(nonce) != AESGCMNonceBytes {
		return nil, ErrInvalidContentNonce
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce, plaintext, aad), nil
}

// OpenContentAES256GCM opens an AES-256-GCM ciphertext with caller-provided AAD.
func OpenContentAES256GCM(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	if len(key) != AES256GCMKeyBytes {
		return nil, ErrInvalidContentKey
	}
	if len(nonce) != AESGCMNonceBytes {
		return nil, ErrInvalidContentNonce
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrContentAuthFailed
	}
	return plaintext, nil
}
