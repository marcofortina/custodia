// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package client

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"custodia/internal/clientcrypto"
)

// NewCryptoClient layers local encryption/decryption on top of the transport client.
//
// The server still receives only opaque ciphertext, metadata and recipient
// envelopes; plaintext and DEKs never cross this boundary.
func NewCryptoClient(transport *Client, options CryptoOptions) (*CryptoClient, error) {
	if transport == nil {
		return nil, fmt.Errorf("transport client is required")
	}
	if err := options.Validate(); err != nil {
		return nil, err
	}
	return &CryptoClient{transport: transport, options: options}, nil
}

func (c *Client) WithCrypto(options CryptoOptions) (*CryptoClient, error) {
	return NewCryptoClient(c, options)
}

// CreateEncryptedSecret encrypts plaintext locally and uploads only opaque blobs.
// The creator is automatically included as a recipient so the secret remains
// readable by the client that created it.
func (c *CryptoClient) CreateEncryptedSecret(ctx context.Context, req CreateEncryptedSecretRequest) (SecretVersionRef, error) {
	namespace, key, legacyName, err := normalizeSecretKeyRequest(req.Namespace, req.Key, req.Name)
	if err != nil {
		return SecretVersionRef{}, err
	}
	dek, nonce, err := c.generateContentKeyAndNonce()
	if err != nil {
		return SecretVersionRef{}, err
	}
	aadInputs := clientcrypto.CanonicalAADInputs{Namespace: namespace, Key: key}
	metadata := clientcrypto.MetadataV1(aadInputs, base64.StdEncoding.EncodeToString(nonce))
	aad, metadataJSON, err := encodeCryptoMetadata(metadata, aadInputs)
	if err != nil {
		return SecretVersionRef{}, err
	}
	ciphertext, err := clientcrypto.SealContentAES256GCM(dek, nonce, req.Plaintext, aad)
	if err != nil {
		return SecretVersionRef{}, mapClientCryptoError(err)
	}
	recipients, err := c.normalizedRecipients(ctx, req.Recipients)
	if err != nil {
		return SecretVersionRef{}, err
	}
	envelopes, err := c.sealRecipientEnvelopes(ctx, recipients, dek, aad)
	if err != nil {
		return SecretVersionRef{}, err
	}
	return c.transport.CreateSecretPayload(CreateSecretPayload{
		Namespace:      namespace,
		Key:            key,
		Name:           legacyName,
		Ciphertext:     base64.StdEncoding.EncodeToString(ciphertext),
		CryptoMetadata: metadataJSON,
		Envelopes:      envelopes,
		Permissions:    req.Permissions,
		ExpiresAt:      req.ExpiresAt,
	})
}

func (c *CryptoClient) CreateEncryptedSecretVersion(ctx context.Context, secretID string, req CreateEncryptedSecretVersionRequest) (SecretVersionRef, error) {
	if strings.TrimSpace(secretID) == "" {
		return SecretVersionRef{}, fmt.Errorf("secret id is required")
	}
	payload, err := c.buildEncryptedSecretVersionPayload(ctx, clientcrypto.CanonicalAADInputs{Namespace: req.Namespace, Key: req.Key}, req)
	if err != nil {
		return SecretVersionRef{}, err
	}
	return c.transport.CreateSecretVersionPayload(secretID, payload)
}

func (c *CryptoClient) CreateEncryptedSecretVersionByKey(ctx context.Context, namespace, key string, req CreateEncryptedSecretVersionRequest) (SecretVersionRef, error) {
	namespace, key, _, err := normalizeSecretKeyRequest(firstNonEmpty(namespace, req.Namespace), firstNonEmpty(key, req.Key), "")
	if err != nil {
		return SecretVersionRef{}, err
	}
	payload, err := c.buildEncryptedSecretVersionPayload(ctx, clientcrypto.CanonicalAADInputs{Namespace: namespace, Key: key}, req)
	if err != nil {
		return SecretVersionRef{}, err
	}
	return c.transport.CreateSecretVersionPayloadByKey(namespace, key, payload)
}

func (c *CryptoClient) buildEncryptedSecretVersionPayload(ctx context.Context, aadInputs clientcrypto.CanonicalAADInputs, req CreateEncryptedSecretVersionRequest) (CreateSecretVersionPayload, error) {
	dek, nonce, err := c.generateContentKeyAndNonce()
	if err != nil {
		return CreateSecretVersionPayload{}, err
	}
	metadata := clientcrypto.MetadataV1(aadInputs, base64.StdEncoding.EncodeToString(nonce))
	aad, metadataJSON, err := encodeCryptoMetadata(metadata, aadInputs)
	if err != nil {
		return CreateSecretVersionPayload{}, err
	}
	ciphertext, err := clientcrypto.SealContentAES256GCM(dek, nonce, req.Plaintext, aad)
	if err != nil {
		return CreateSecretVersionPayload{}, mapClientCryptoError(err)
	}
	recipients, err := c.normalizedRecipients(ctx, req.Recipients)
	if err != nil {
		return CreateSecretVersionPayload{}, err
	}
	envelopes, err := c.sealRecipientEnvelopes(ctx, recipients, dek, aad)
	if err != nil {
		return CreateSecretVersionPayload{}, err
	}
	return CreateSecretVersionPayload{
		Ciphertext:     base64.StdEncoding.EncodeToString(ciphertext),
		CryptoMetadata: metadataJSON,
		Envelopes:      envelopes,
		Permissions:    req.Permissions,
		ExpiresAt:      req.ExpiresAt,
	}, nil
}

// ReadDecryptedSecret downloads the caller's authorized envelope and opens it locally.
// Authentication failures are mapped to stable SDK errors instead of exposing
// low-level crypto library details.
func (c *CryptoClient) ReadDecryptedSecret(ctx context.Context, secretID string) (DecryptedSecret, error) {
	secret, err := c.transport.GetSecretPayload(secretID)
	if err != nil {
		return DecryptedSecret{}, err
	}
	return c.openDecryptedSecret(ctx, secret, clientcrypto.CanonicalAADInputs{Namespace: secret.Namespace, Key: secret.Key})
}

func (c *CryptoClient) ReadDecryptedSecretByKey(ctx context.Context, namespace, key string) (DecryptedSecret, error) {
	namespace, key, _, err := normalizeSecretKeyRequest(namespace, key, "")
	if err != nil {
		return DecryptedSecret{}, err
	}
	secret, err := c.transport.GetSecretPayloadByKey(namespace, key)
	if err != nil {
		return DecryptedSecret{}, err
	}
	return c.openDecryptedSecret(ctx, secret, clientcrypto.CanonicalAADInputs{Namespace: namespace, Key: key})
}

func (c *CryptoClient) openDecryptedSecret(ctx context.Context, secret SecretReadResponse, fallback clientcrypto.CanonicalAADInputs) (DecryptedSecret, error) {
	metadata, aad, err := decodeCryptoMetadata(secret.CryptoMetadata, fallback)
	if err != nil {
		return DecryptedSecret{}, err
	}
	if metadata.ContentNonce == "" {
		return DecryptedSecret{}, ErrMalformedCryptoMetadata
	}
	nonce, err := base64.StdEncoding.DecodeString(metadata.ContentNonce)
	if err != nil {
		return DecryptedSecret{}, ErrMalformedCryptoMetadata
	}
	dek, err := c.openSecretEnvelope(ctx, secret.Envelope, aad)
	if err != nil {
		return DecryptedSecret{}, err
	}
	ciphertext, err := base64.StdEncoding.DecodeString(secret.Ciphertext)
	if err != nil {
		return DecryptedSecret{}, ErrMalformedCryptoMetadata
	}
	plaintext, err := clientcrypto.OpenContentAES256GCM(dek, nonce, ciphertext, aad)
	if err != nil {
		return DecryptedSecret{}, mapClientCryptoError(err)
	}
	return DecryptedSecret{
		SecretID:        secret.SecretID,
		Namespace:       secret.Namespace,
		Key:             secret.Key,
		VersionID:       secret.VersionID,
		Plaintext:       plaintext,
		CryptoMetadata:  append([]byte{}, secret.CryptoMetadata...),
		Permissions:     secret.Permissions,
		GrantedAt:       secret.GrantedAt,
		AccessExpiresAt: secret.AccessExpiresAt,
	}, nil
}

// ShareEncryptedSecret rewraps the existing DEK for a new recipient.
// The server authorizes the share operation but does not learn the DEK or the
// recipient public key trust source used by the client.
func (c *CryptoClient) ShareEncryptedSecret(ctx context.Context, secretID string, req ShareEncryptedSecretRequest) error {
	if strings.TrimSpace(req.TargetClientID) == "" {
		return fmt.Errorf("target client id is required")
	}
	secret, err := c.transport.GetSecretPayload(secretID)
	if err != nil {
		return err
	}
	payload, err := c.buildShareSecretPayload(ctx, secret, req)
	if err != nil {
		return err
	}
	return c.transport.ShareSecretPayload(secretID, payload)
}

func (c *CryptoClient) ShareEncryptedSecretByKey(ctx context.Context, namespace, key string, req ShareEncryptedSecretRequest) error {
	namespace, key, _, err := normalizeSecretKeyRequest(firstNonEmpty(namespace, req.Namespace), firstNonEmpty(key, req.Key), "")
	if err != nil {
		return err
	}
	if strings.TrimSpace(req.TargetClientID) == "" {
		return fmt.Errorf("target client id is required")
	}
	secret, err := c.transport.GetSecretPayloadByKey(namespace, key)
	if err != nil {
		return err
	}
	payload, err := c.buildShareSecretPayload(ctx, secret, req)
	if err != nil {
		return err
	}
	return c.transport.ShareSecretPayloadByKey(namespace, key, payload)
}

func (c *CryptoClient) buildShareSecretPayload(ctx context.Context, secret SecretReadResponse, req ShareEncryptedSecretRequest) (ShareSecretPayload, error) {
	_, aad, err := decodeCryptoMetadata(secret.CryptoMetadata, clientcrypto.CanonicalAADInputs{Namespace: secret.Namespace, Key: secret.Key})
	if err != nil {
		return ShareSecretPayload{}, err
	}
	dek, err := c.openSecretEnvelope(ctx, secret.Envelope, aad)
	if err != nil {
		return ShareSecretPayload{}, err
	}
	envelopes, err := c.sealRecipientEnvelopes(ctx, []string{req.TargetClientID}, dek, aad)
	if err != nil {
		return ShareSecretPayload{}, err
	}
	if len(envelopes) != 1 {
		return ShareSecretPayload{}, ErrMissingRecipientEnvelope
	}
	return ShareSecretPayload{
		VersionID:      secret.VersionID,
		TargetClientID: req.TargetClientID,
		Envelope:       envelopes[0].Envelope,
		Permissions:    req.Permissions,
		ExpiresAt:      req.ExpiresAt,
	}, nil
}

func normalizeSecretKeyRequest(namespace, key, legacyName string) (string, string, string, error) {
	namespace = strings.TrimSpace(namespace)
	if namespace == "" {
		namespace = "default"
	}
	key = strings.TrimSpace(key)
	legacyName = strings.TrimSpace(legacyName)
	if key == "" {
		key = legacyName
	}
	if key == "" {
		return "", "", "", fmt.Errorf("secret key is required")
	}
	return namespace, key, firstNonEmpty(legacyName, key), nil
}

func (c *CryptoClient) generateContentKeyAndNonce() ([]byte, []byte, error) {
	dek, err := readRandomBytes(c.options.RandomSource, clientcrypto.AES256GCMKeyBytes)
	if err != nil {
		return nil, nil, err
	}
	nonce, err := readRandomBytes(c.options.RandomSource, clientcrypto.AESGCMNonceBytes)
	if err != nil {
		return nil, nil, err
	}
	return dek, nonce, nil
}

// normalizedRecipients de-duplicates requested recipients and prepends the
// local client identity. This prevents accidental creation of unreadable
// secrets when callers forget to include themselves.
func (c *CryptoClient) normalizedRecipients(ctx context.Context, requested []string) ([]string, error) {
	current, err := c.options.PrivateKeyProvider.CurrentPrivateKey(ctx)
	if err != nil {
		return nil, err
	}
	recipients := make([]string, 0, len(requested)+1)
	seen := map[string]bool{}
	if current.ClientID() != "" {
		recipients = append(recipients, current.ClientID())
		seen[current.ClientID()] = true
	}
	for _, recipient := range requested {
		recipient = strings.TrimSpace(recipient)
		if recipient == "" || seen[recipient] {
			continue
		}
		recipients = append(recipients, recipient)
		seen[recipient] = true
	}
	if len(recipients) == 0 {
		return nil, ErrMissingRecipientEnvelope
	}
	return recipients, nil
}

func (c *CryptoClient) sealRecipientEnvelopes(ctx context.Context, recipients []string, dek []byte, aad []byte) ([]RecipientEnvelope, error) {
	envelopes := make([]RecipientEnvelope, 0, len(recipients))
	for _, recipientID := range recipients {
		publicKey, err := c.options.PublicKeyResolver.ResolveRecipientPublicKey(ctx, recipientID)
		if err != nil {
			return nil, err
		}
		if publicKey.Scheme != CryptoEnvelopeHPKEV1 {
			return nil, ErrUnsupportedEnvelopeScheme
		}
		ephemeralPrivateKey, err := readRandomBytes(c.options.RandomSource, 32)
		if err != nil {
			return nil, err
		}
		envelope, err := clientcrypto.SealHPKEV1Envelope(publicKey.PublicKey, ephemeralPrivateKey, dek, aad)
		if err != nil {
			return nil, mapClientCryptoError(err)
		}
		envelopes = append(envelopes, RecipientEnvelope{ClientID: recipientID, Envelope: clientcrypto.EncodeEnvelope(envelope)})
	}
	return envelopes, nil
}

func (c *CryptoClient) openSecretEnvelope(ctx context.Context, encodedEnvelope string, aad []byte) ([]byte, error) {
	envelope, err := clientcrypto.DecodeEnvelope(encodedEnvelope)
	if err != nil {
		return nil, mapClientCryptoError(err)
	}
	privateKey, err := c.options.PrivateKeyProvider.CurrentPrivateKey(ctx)
	if err != nil {
		return nil, err
	}
	if privateKey.Scheme() != CryptoEnvelopeHPKEV1 {
		return nil, ErrUnsupportedEnvelopeScheme
	}
	dek, err := privateKey.OpenEnvelope(ctx, envelope, aad)
	if err != nil {
		return nil, err
	}
	return dek, nil
}

func encodeCryptoMetadata(metadata clientcrypto.Metadata, aadInputs clientcrypto.CanonicalAADInputs) ([]byte, json.RawMessage, error) {
	aad, err := clientcrypto.BuildCanonicalAAD(metadata, aadInputs)
	if err != nil {
		return nil, nil, mapClientCryptoError(err)
	}
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return nil, nil, err
	}
	return aad, metadataJSON, nil
}

func decodeCryptoMetadata(payload json.RawMessage, fallbackAAD clientcrypto.CanonicalAADInputs) (clientcrypto.Metadata, []byte, error) {
	metadata, err := clientcrypto.ParseMetadata(payload)
	if err != nil {
		return clientcrypto.Metadata{}, nil, mapClientCryptoError(err)
	}
	aadInputs := metadata.CanonicalAADInputs(fallbackAAD)
	aad, err := clientcrypto.BuildCanonicalAAD(metadata, aadInputs)
	if err != nil {
		return clientcrypto.Metadata{}, nil, mapClientCryptoError(err)
	}
	return metadata, aad, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func readRandomBytes(random io.Reader, length int) ([]byte, error) {
	buf := make([]byte, length)
	if _, err := io.ReadFull(random, buf); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRandomSourceFailed, err)
	}
	return buf, nil
}
