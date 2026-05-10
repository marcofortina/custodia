// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"custodia/internal/clientcrypto"
)

type staticPublicKeyResolver map[string]RecipientPublicKey

func (resolver staticPublicKeyResolver) ResolveRecipientPublicKey(_ context.Context, clientID string) (RecipientPublicKey, error) {
	key, ok := resolver[clientID]
	if !ok {
		return RecipientPublicKey{}, errors.New("missing recipient public key")
	}
	return key, nil
}

type staticPrivateKeyProvider struct{ handle PrivateKeyHandle }

func (provider staticPrivateKeyProvider) CurrentPrivateKey(context.Context) (PrivateKeyHandle, error) {
	return provider.handle, nil
}

func TestGoCryptoClientCreateEncryptedSecretPostsOpaquePayload(t *testing.T) {
	alicePrivate := bytes.Repeat([]byte("1"), 32)
	bobPrivate := bytes.Repeat([]byte("2"), 32)
	aliceHandle := mustX25519Handle(t, "client_alice", alicePrivate)
	resolver := mustResolver(t, map[string][]byte{"client_alice": alicePrivate, "client_bob": bobPrivate})

	var received CreateSecretPayload
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.EscapedPath() != "/v1/secrets" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.EscapedPath())
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		_ = json.NewEncoder(w).Encode(SecretVersionRef{SecretID: "secret-id", VersionID: "version-id"})
	}))
	defer server.Close()

	cryptoClient := mustCryptoClient(t, server, resolver, aliceHandle, deterministicRandom(
		bytes.Repeat([]byte("Q"), 32),
		bytes.Repeat([]byte("a"), 12),
		bytes.Repeat([]byte("A"), 32),
		bytes.Repeat([]byte("B"), 32),
	))
	created, err := cryptoClient.CreateEncryptedSecret(context.Background(), CreateEncryptedSecretRequest{
		Namespace:   "db01",
		Key:         "user:sys",
		Plaintext:   []byte("correct horse battery staple"),
		Recipients:  []string{"client_bob"},
		Permissions: PermissionAll,
	})
	if err != nil {
		t.Fatalf("CreateEncryptedSecret() error = %v", err)
	}
	if created.SecretID != "secret-id" || created.VersionID != "version-id" {
		t.Fatalf("created = %+v", created)
	}
	if received.Namespace != "db01" || received.Key != "user:sys" || received.Name != "user:sys" || received.Permissions != PermissionAll {
		t.Fatalf("received = %+v", received)
	}
	if len(received.Envelopes) != 2 || received.Envelopes[0].ClientID != "client_alice" || received.Envelopes[1].ClientID != "client_bob" {
		t.Fatalf("envelopes = %+v", received.Envelopes)
	}
	metadata, aad := mustParseMetadataAndAAD(t, received.CryptoMetadata, clientcrypto.CanonicalAADInputs{SecretName: "user:sys"})
	if metadata.AAD == nil || metadata.AAD.SecretName != "user:sys" || metadata.ContentNonce == "" {
		t.Fatalf("metadata = %+v", metadata)
	}
	plaintext := mustOpenPostedSecret(t, aliceHandle, received.Ciphertext, received.Envelopes[0].Envelope, metadata.ContentNonce, aad)
	if string(plaintext) != "correct horse battery staple" {
		t.Fatalf("plaintext = %q", plaintext)
	}
	if decoded, _ := base64.StdEncoding.DecodeString(received.Ciphertext); bytes.Contains(decoded, []byte("correct horse")) {
		t.Fatal("ciphertext contains plaintext")
	}
}

func TestGoCryptoClientReadDecryptedSecret(t *testing.T) {
	alicePrivate := bytes.Repeat([]byte("1"), 32)
	aliceHandle := mustX25519Handle(t, "client_alice", alicePrivate)
	response := buildEncryptedReadResponse(t, "secret-id", "version-id", []byte("server stored ciphertext only"), alicePrivate, bytes.Repeat([]byte("C"), 32))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.EscapedPath() != "/v1/secrets/secret-id" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.EscapedPath())
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	cryptoClient := mustCryptoClient(t, server, staticPublicKeyResolver{}, aliceHandle, bytes.NewReader(nil))
	secret, err := cryptoClient.ReadDecryptedSecret(context.Background(), "secret-id")
	if err != nil {
		t.Fatalf("ReadDecryptedSecret() error = %v", err)
	}
	if string(secret.Plaintext) != "server stored ciphertext only" || secret.SecretID != "secret-id" || secret.VersionID != "version-id" {
		t.Fatalf("secret = %+v", secret)
	}
}

func TestGoCryptoClientReadDecryptedSecretByKey(t *testing.T) {
	alicePrivate := bytes.Repeat([]byte("1"), 32)
	aliceHandle := mustX25519Handle(t, "client_alice", alicePrivate)
	response := buildEncryptedReadResponse(t, "secret-id", "version-id", []byte("server stored ciphertext only"), alicePrivate, bytes.Repeat([]byte("C"), 32))
	response.Namespace = "db01"
	response.Key = "user:sys"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.EscapedPath() != "/v1/secrets/by-key" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.EscapedPath())
		}
		if got := r.URL.Query().Get("namespace"); got != "db01" {
			t.Fatalf("namespace = %q", got)
		}
		if got := r.URL.Query().Get("key"); got != "user:sys" {
			t.Fatalf("key = %q", got)
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	cryptoClient := mustCryptoClient(t, server, staticPublicKeyResolver{}, aliceHandle, bytes.NewReader(nil))
	secret, err := cryptoClient.ReadDecryptedSecretByKey(context.Background(), "db01", "user:sys")
	if err != nil {
		t.Fatalf("ReadDecryptedSecretByKey() error = %v", err)
	}
	if string(secret.Plaintext) != "server stored ciphertext only" || secret.Namespace != "db01" || secret.Key != "user:sys" {
		t.Fatalf("secret = %+v", secret)
	}
}

func TestGoCryptoClientShareEncryptedSecretAddsRecipientEnvelope(t *testing.T) {
	alicePrivate := bytes.Repeat([]byte("1"), 32)
	bobPrivate := bytes.Repeat([]byte("2"), 32)
	aliceHandle := mustX25519Handle(t, "client_alice", alicePrivate)
	resolver := mustResolver(t, map[string][]byte{"client_bob": bobPrivate})
	response := buildEncryptedReadResponse(t, "secret-id", "version-id", []byte("share existing DEK"), alicePrivate, bytes.Repeat([]byte("C"), 32))

	var shared ShareSecretPayload
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.EscapedPath() {
		case "GET /v1/secrets/secret-id":
			_ = json.NewEncoder(w).Encode(response)
		case "POST /v1/secrets/secret-id/share":
			if err := json.NewDecoder(r.Body).Decode(&shared); err != nil {
				t.Fatalf("decode share request: %v", err)
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "shared"})
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.EscapedPath())
		}
	}))
	defer server.Close()

	cryptoClient := mustCryptoClient(t, server, resolver, aliceHandle, deterministicRandom(bytes.Repeat([]byte("D"), 32)))
	if err := cryptoClient.ShareEncryptedSecret(context.Background(), "secret-id", ShareEncryptedSecretRequest{TargetClientID: "client_bob", Permissions: PermissionRead}); err != nil {
		t.Fatalf("ShareEncryptedSecret() error = %v", err)
	}
	if shared.VersionID != "version-id" || shared.TargetClientID != "client_bob" || shared.Permissions != PermissionRead {
		t.Fatalf("shared = %+v", shared)
	}
	_, aad := mustParseMetadataAndAAD(t, response.CryptoMetadata, clientcrypto.CanonicalAADInputs{SecretID: "secret-id", VersionID: "version-id"})
	bobHandle := mustX25519Handle(t, "client_bob", bobPrivate)
	opened, err := bobHandle.OpenEnvelope(context.Background(), mustDecodeEnvelope(t, shared.Envelope), aad)
	if err != nil {
		t.Fatalf("bob OpenEnvelope() error = %v", err)
	}
	if !bytes.Equal(opened, bytes.Repeat([]byte("S"), 32)) {
		t.Fatalf("shared DEK mismatch")
	}
}

func TestGoCryptoClientShareEncryptedSecretByKeyAddsRecipientEnvelope(t *testing.T) {
	alicePrivate := bytes.Repeat([]byte("1"), 32)
	bobPrivate := bytes.Repeat([]byte("2"), 32)
	aliceHandle := mustX25519Handle(t, "client_alice", alicePrivate)
	resolver := mustResolver(t, map[string][]byte{"client_bob": bobPrivate})
	response := buildEncryptedReadResponse(t, "secret-id", "version-id", []byte("share existing DEK"), alicePrivate, bytes.Repeat([]byte("C"), 32))

	var shared ShareSecretPayload
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.EscapedPath() {
		case "GET /v1/secrets/by-key":
			_ = json.NewEncoder(w).Encode(response)
		case "POST /v1/secrets/by-key/share":
			if err := json.NewDecoder(r.Body).Decode(&shared); err != nil {
				t.Fatalf("decode share request: %v", err)
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "shared"})
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.EscapedPath())
		}
	}))
	defer server.Close()

	cryptoClient := mustCryptoClient(t, server, resolver, aliceHandle, deterministicRandom(bytes.Repeat([]byte("D"), 32)))
	if err := cryptoClient.ShareEncryptedSecretByKey(context.Background(), "db01", "user:sys", ShareEncryptedSecretRequest{TargetClientID: "client_bob", Permissions: PermissionRead}); err != nil {
		t.Fatalf("ShareEncryptedSecretByKey() error = %v", err)
	}
	if shared.VersionID != "version-id" || shared.TargetClientID != "client_bob" || shared.Permissions != PermissionRead {
		t.Fatalf("shared = %+v", shared)
	}
}

func TestGoCryptoClientCreateEncryptedSecretVersion(t *testing.T) {
	alicePrivate := bytes.Repeat([]byte("1"), 32)
	aliceHandle := mustX25519Handle(t, "client_alice", alicePrivate)
	resolver := mustResolver(t, map[string][]byte{"client_alice": alicePrivate})

	var received CreateSecretVersionPayload
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.EscapedPath() != "/v1/secrets/secret-id/versions" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.EscapedPath())
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		_ = json.NewEncoder(w).Encode(SecretVersionRef{SecretID: "secret-id", VersionID: "new-version"})
	}))
	defer server.Close()

	cryptoClient := mustCryptoClient(t, server, resolver, aliceHandle, deterministicRandom(
		bytes.Repeat([]byte("V"), 32),
		bytes.Repeat([]byte("v"), 12),
		bytes.Repeat([]byte("E"), 32),
	))
	created, err := cryptoClient.CreateEncryptedSecretVersion(context.Background(), "secret-id", CreateEncryptedSecretVersionRequest{Plaintext: []byte("rotated secret"), Permissions: PermissionRead})
	if err != nil {
		t.Fatalf("CreateEncryptedSecretVersion() error = %v", err)
	}
	if created.VersionID != "new-version" {
		t.Fatalf("created = %+v", created)
	}
	metadata, aad := mustParseMetadataAndAAD(t, received.CryptoMetadata, clientcrypto.CanonicalAADInputs{SecretID: "secret-id"})
	if metadata.AAD == nil || metadata.AAD.SecretID != "secret-id" {
		t.Fatalf("metadata = %+v", metadata)
	}
	plaintext := mustOpenPostedSecret(t, aliceHandle, received.Ciphertext, received.Envelopes[0].Envelope, metadata.ContentNonce, aad)
	if string(plaintext) != "rotated secret" {
		t.Fatalf("plaintext = %q", plaintext)
	}
}

func TestGoCryptoClientCreateEncryptedSecretVersionByKey(t *testing.T) {
	alicePrivate := bytes.Repeat([]byte("1"), 32)
	aliceHandle := mustX25519Handle(t, "client_alice", alicePrivate)
	resolver := mustResolver(t, map[string][]byte{"client_alice": alicePrivate})

	var received CreateSecretVersionPayload
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.EscapedPath() != "/v1/secrets/by-key/versions" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.EscapedPath())
		}
		if got := r.URL.Query().Get("namespace"); got != "db01" {
			t.Fatalf("namespace = %q", got)
		}
		if got := r.URL.Query().Get("key"); got != "user:sys" {
			t.Fatalf("key = %q", got)
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		_ = json.NewEncoder(w).Encode(SecretVersionRef{SecretID: "secret-id", VersionID: "new-version"})
	}))
	defer server.Close()

	cryptoClient := mustCryptoClient(t, server, resolver, aliceHandle, deterministicRandom(
		bytes.Repeat([]byte("V"), 32),
		bytes.Repeat([]byte("v"), 12),
		bytes.Repeat([]byte("E"), 32),
	))
	created, err := cryptoClient.CreateEncryptedSecretVersionByKey(context.Background(), "db01", "user:sys", CreateEncryptedSecretVersionRequest{Plaintext: []byte("rotated secret"), Permissions: PermissionRead})
	if err != nil {
		t.Fatalf("CreateEncryptedSecretVersionByKey() error = %v", err)
	}
	if created.VersionID != "new-version" {
		t.Fatalf("created = %+v", created)
	}
	metadata, _ := mustParseMetadataAndAAD(t, received.CryptoMetadata, clientcrypto.CanonicalAADInputs{SecretName: "user:sys"})
	if metadata.AAD == nil || metadata.AAD.SecretName != "user:sys" {
		t.Fatalf("metadata = %+v", metadata)
	}
}

func TestX25519PrivateKeyHandleRejectsWrongRecipient(t *testing.T) {
	alicePrivate := bytes.Repeat([]byte("1"), 32)
	bobPrivate := bytes.Repeat([]byte("2"), 32)
	alicePublic := mustPublicKey(t, "client_alice", alicePrivate)
	bobHandle := mustX25519Handle(t, "client_bob", bobPrivate)
	aad := []byte("aad")
	envelope, err := clientcrypto.SealHPKEV1Envelope(alicePublic.PublicKey, bytes.Repeat([]byte("A"), 32), bytes.Repeat([]byte("Q"), 32), aad)
	if err != nil {
		t.Fatalf("SealHPKEV1Envelope() error = %v", err)
	}
	if _, err := bobHandle.OpenEnvelope(context.Background(), envelope, aad); !errors.Is(err, ErrWrongRecipient) {
		t.Fatalf("OpenEnvelope() error = %v, want ErrWrongRecipient", err)
	}
}

func mustCryptoClient(t *testing.T, server *httptest.Server, resolver PublicKeyResolver, privateKey PrivateKeyHandle, random io.Reader) *CryptoClient {
	t.Helper()
	cryptoClient, err := NewCryptoClient(&Client{baseURL: server.URL, http: server.Client()}, CryptoOptions{
		PublicKeyResolver:  resolver,
		PrivateKeyProvider: staticPrivateKeyProvider{handle: privateKey},
		RandomSource:       random,
		Clock:              fixedClock{},
	})
	if err != nil {
		t.Fatalf("NewCryptoClient() error = %v", err)
	}
	return cryptoClient
}

func deterministicRandom(chunks ...[]byte) *bytes.Reader {
	return bytes.NewReader(bytes.Join(chunks, nil))
}

func mustResolver(t *testing.T, keys map[string][]byte) staticPublicKeyResolver {
	t.Helper()
	resolver := staticPublicKeyResolver{}
	for clientID, privateKey := range keys {
		resolver[clientID] = mustPublicKey(t, clientID, privateKey)
	}
	return resolver
}

func mustPublicKey(t *testing.T, clientID string, privateKey []byte) RecipientPublicKey {
	t.Helper()
	publicKey, err := DeriveX25519RecipientPublicKey(clientID, privateKey)
	if err != nil {
		t.Fatalf("DeriveX25519RecipientPublicKey() error = %v", err)
	}
	return publicKey
}

func mustX25519Handle(t *testing.T, clientID string, privateKey []byte) X25519PrivateKeyHandle {
	t.Helper()
	handle, err := NewX25519PrivateKeyHandle(clientID, privateKey)
	if err != nil {
		t.Fatalf("NewX25519PrivateKeyHandle() error = %v", err)
	}
	return handle
}

func buildEncryptedReadResponse(t *testing.T, secretID string, versionID string, plaintext []byte, recipientPrivateKey []byte, ephemeralPrivateKey []byte) SecretReadResponse {
	t.Helper()
	dek := bytes.Repeat([]byte("S"), 32)
	nonce := bytes.Repeat([]byte("c"), 12)
	aadInputs := clientcrypto.CanonicalAADInputs{SecretID: secretID, VersionID: versionID}
	metadata := clientcrypto.MetadataV1(aadInputs, base64.StdEncoding.EncodeToString(nonce))
	aad, metadataJSON, err := encodeCryptoMetadata(metadata, aadInputs)
	if err != nil {
		t.Fatalf("encodeCryptoMetadata() error = %v", err)
	}
	ciphertext, err := clientcrypto.SealContentAES256GCM(dek, nonce, plaintext, aad)
	if err != nil {
		t.Fatalf("SealContentAES256GCM() error = %v", err)
	}
	recipientPublic := mustPublicKey(t, "client_alice", recipientPrivateKey)
	envelope, err := clientcrypto.SealHPKEV1Envelope(recipientPublic.PublicKey, ephemeralPrivateKey, dek, aad)
	if err != nil {
		t.Fatalf("SealHPKEV1Envelope() error = %v", err)
	}
	return SecretReadResponse{
		SecretID:        secretID,
		VersionID:       versionID,
		Ciphertext:      base64.StdEncoding.EncodeToString(ciphertext),
		CryptoMetadata:  metadataJSON,
		Envelope:        clientcrypto.EncodeEnvelope(envelope),
		Permissions:     PermissionRead,
		AccessExpiresAt: nil,
	}
}

func mustParseMetadataAndAAD(t *testing.T, payload json.RawMessage, fallback clientcrypto.CanonicalAADInputs) (clientcrypto.Metadata, []byte) {
	t.Helper()
	metadata, aad, err := decodeCryptoMetadata(payload, fallback)
	if err != nil {
		t.Fatalf("decodeCryptoMetadata() error = %v", err)
	}
	return metadata, aad
}

func mustOpenPostedSecret(t *testing.T, handle X25519PrivateKeyHandle, encodedCiphertext string, encodedEnvelope string, encodedNonce string, aad []byte) []byte {
	t.Helper()
	dek, err := handle.OpenEnvelope(context.Background(), mustDecodeEnvelope(t, encodedEnvelope), aad)
	if err != nil {
		t.Fatalf("OpenEnvelope() error = %v", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(encodedCiphertext)
	if err != nil {
		t.Fatalf("DecodeString(ciphertext) error = %v", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(encodedNonce)
	if err != nil {
		t.Fatalf("DecodeString(nonce) error = %v", err)
	}
	plaintext, err := clientcrypto.OpenContentAES256GCM(dek, nonce, ciphertext, aad)
	if err != nil {
		t.Fatalf("OpenContentAES256GCM() error = %v", err)
	}
	return plaintext
}

func mustDecodeEnvelope(t *testing.T, encoded string) []byte {
	t.Helper()
	envelope, err := clientcrypto.DecodeEnvelope(encoded)
	if err != nil {
		t.Fatalf("DecodeEnvelope() error = %v", err)
	}
	return envelope
}

func TestGoCryptoClientRejectsRandomSourceFailures(t *testing.T) {
	alicePrivate := bytes.Repeat([]byte("1"), 32)
	aliceHandle := mustX25519Handle(t, "client_alice", alicePrivate)
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()
	cryptoClient := mustCryptoClient(t, server, mustResolver(t, map[string][]byte{"client_alice": alicePrivate}), aliceHandle, strings.NewReader("short"))
	_, err := cryptoClient.CreateEncryptedSecret(context.Background(), CreateEncryptedSecretRequest{Name: "secret", Plaintext: []byte("value"), Permissions: PermissionRead})
	if !errors.Is(err, ErrRandomSourceFailed) {
		t.Fatalf("CreateEncryptedSecret() error = %v, want ErrRandomSourceFailed", err)
	}
}
