// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package client_test

import (
	"bytes"
	"context"
	"time"

	custodia "custodia/pkg/client"
)

type exampleResolver struct{}

func (exampleResolver) ResolveRecipientPublicKey(_ context.Context, clientID string) (custodia.RecipientPublicKey, error) {
	return custodia.RecipientPublicKey{ClientID: clientID, Scheme: custodia.CryptoEnvelopeHPKEV1, PublicKey: []byte("recipient-public-key")}, nil
}

type examplePrivateKey struct{}

func (examplePrivateKey) ClientID() string { return "client_alice" }
func (examplePrivateKey) Scheme() string   { return custodia.CryptoEnvelopeHPKEV1 }
func (examplePrivateKey) OpenEnvelope(_ context.Context, envelope []byte, _ []byte) ([]byte, error) {
	return envelope, nil
}

type examplePrivateKeyProvider struct{}

func (examplePrivateKeyProvider) CurrentPrivateKey(context.Context) (custodia.PrivateKeyHandle, error) {
	return examplePrivateKey{}, nil
}

type exampleClock struct{}

func (exampleClock) Now() time.Time { return time.Unix(1, 0).UTC() }

func ExampleNew() {
	transport, err := custodia.New(custodia.Config{
		ServerURL: "https://custodia.example.internal:8443",
		CertFile:  "/home/alice/.config/custodia/client_alice/client_alice.crt",
		KeyFile:   "/home/alice/.config/custodia/client_alice/client_alice.key",
		CAFile:    "/home/alice/.config/custodia/client_alice/ca.crt",
	})
	if err != nil {
		// Handle missing files, TLS configuration errors or invalid paths.
		return
	}
	_ = transport
}

func ExampleClient_CreateSecretPayload() {
	var transport *custodia.Client

	_, _ = transport.CreateSecretPayload(custodia.CreateSecretPayload{
		Namespace:  "db01",
		Key:        "user:sys",
		Ciphertext: "base64-opaque-ciphertext",
		CryptoMetadata: []byte(`{
			"version":"custodia.client-crypto.v1",
			"content_cipher":"aes-256-gcm"
		}`),
		Envelopes: []custodia.RecipientEnvelope{
			{ClientID: "client_alice", Envelope: "base64-opaque-envelope"},
		},
		Permissions: custodia.PermissionRead,
	})
}

func ExampleClient_GetSecretPayloadByKey() {
	var transport *custodia.Client

	secret, err := transport.GetSecretPayloadByKey("db01", "user:sys")
	if err != nil {
		return
	}
	_ = secret.Ciphertext // Opaque ciphertext; decrypt only in the caller process.
}

func ExampleClient_CreateSecretVersionPayloadByKey() {
	var transport *custodia.Client

	_, _ = transport.CreateSecretVersionPayloadByKey("db01", "user:sys", custodia.CreateSecretVersionPayload{
		Ciphertext: "base64-opaque-rotated-ciphertext",
		Envelopes: []custodia.RecipientEnvelope{
			{ClientID: "client_alice", Envelope: "base64-opaque-envelope"},
		},
		Permissions: custodia.PermissionRead,
	})
}

func ExampleClient_ShareSecretPayloadByKey() {
	var transport *custodia.Client

	_ = transport.ShareSecretPayloadByKey("db01", "user:sys", custodia.ShareSecretPayload{
		VersionID:      "version-id-from-read",
		TargetClientID: "client_bob",
		Envelope:       "base64-opaque-envelope-for-bob",
		Permissions:    custodia.PermissionRead,
	})
}

func ExampleClient_DeleteSecretByKey() {
	var transport *custodia.Client

	_ = transport.DeleteSecretByKey("db01", "user:sys", false)
}

func ExampleNewCryptoClient() {
	var transport *custodia.Client

	cryptoClient, err := custodia.NewCryptoClient(transport, custodia.CryptoOptions{
		PublicKeyResolver:  exampleResolver{},
		PrivateKeyProvider: examplePrivateKeyProvider{},
		RandomSource:       bytes.NewReader(bytes.Repeat([]byte{1}, 64)),
		Clock:              exampleClock{},
	})
	if err != nil {
		return
	}
	_ = cryptoClient
}

func ExampleCryptoClient_CreateEncryptedSecret() {
	var cryptoClient *custodia.CryptoClient

	_, _ = cryptoClient.CreateEncryptedSecret(context.Background(), custodia.CreateEncryptedSecretRequest{
		Namespace:   "db01",
		Key:         "user:sys",
		Plaintext:   []byte("local plaintext never sent to the server"),
		Recipients:  []string{"client_bob"},
		Permissions: custodia.PermissionRead,
	})
}

func ExampleCryptoClient_ReadDecryptedSecretByKey() {
	var cryptoClient *custodia.CryptoClient

	secret, err := cryptoClient.ReadDecryptedSecretByKey(context.Background(), "db01", "user:sys")
	if err != nil {
		return
	}
	_ = secret.Plaintext // Local plaintext returned only by CryptoClient.
}
