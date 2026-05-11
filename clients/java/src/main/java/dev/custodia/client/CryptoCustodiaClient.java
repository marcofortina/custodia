/*
 * Copyright (c) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * This file is part of Custodia.
 * Custodia is distributed under the GNU Affero General Public License v3.0.
 * See the accompanying LICENSE file for details.
 */

package dev.custodia.client;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

public final class CryptoCustodiaClient {
    private final CustodiaClient transport;
    private final CustodiaCrypto.CryptoOptions options;

    CryptoCustodiaClient(CustodiaClient transport, CustodiaCrypto.CryptoOptions options) {
        this.transport = Objects.requireNonNull(transport, "transport");
        this.options = Objects.requireNonNull(options, "options");
    }

    public String createEncryptedSecretByKey(String namespace, String key, byte[] plaintext, List<String> recipients, int permissions)
        throws IOException, InterruptedException, CustodiaHttpError {
        return createEncryptedSecretByKey(namespace, key, plaintext, recipients, permissions, null);
    }

    public String createEncryptedSecretByKey(
        String namespace,
        String key,
        byte[] plaintext,
        List<String> recipients,
        int permissions,
        String expiresAt
    ) throws IOException, InterruptedException, CustodiaHttpError {
        String normalizedNamespace = requireText(namespace, "namespace");
        String normalizedKey = requireText(key, "secret key");
        byte[] dek = random(CustodiaCrypto.AES256_GCM_KEY_BYTES);
        byte[] nonce = random(CustodiaCrypto.AES_GCM_NONCE_BYTES);
        CustodiaCrypto.AADInputs aadInputs = new CustodiaCrypto.AADInputs(normalizedNamespace, normalizedKey, 1);
        CustodiaCrypto.CryptoMetadata metadata = CustodiaCrypto.metadataV1(aadInputs, nonce);
        byte[] aad = CustodiaCrypto.buildCanonicalAAD(metadata, aadInputs);
        byte[] ciphertext = CustodiaCrypto.sealContentAES256GCM(dek, nonce, plaintext, aad);

        StringBuilder payload = new StringBuilder();
        payload.append('{');
        appendField(payload, "namespace", normalizedNamespace);
        payload.append(',');
        appendField(payload, "key", normalizedKey);
        payload.append(',');
        appendField(payload, "ciphertext", CustodiaCrypto.encodeBase64(ciphertext));
        payload.append(',');
        payload.append(CustodiaCrypto.quote("crypto_metadata")).append(':').append(CustodiaCrypto.metadataJson(metadata));
        payload.append(',');
        payload.append(CustodiaCrypto.quote("envelopes")).append(':').append(sealRecipientEnvelopes(normalizedRecipients(recipients), dek, aad));
        payload.append(',');
        payload.append(CustodiaCrypto.quote("permissions")).append(':').append(permissions);
        if (expiresAt != null && !expiresAt.isBlank()) {
            payload.append(',');
            appendField(payload, "expires_at", expiresAt);
        }
        payload.append('}');
        return transport.createSecretPayload(payload.toString());
    }

    public String createEncryptedSecretVersion(String secretId, byte[] plaintext, List<String> recipients, int permissions)
        throws IOException, InterruptedException, CustodiaHttpError {
        return createEncryptedSecretVersion(secretId, plaintext, recipients, permissions, null);
    }

    public String createEncryptedSecretVersion(String secretId, byte[] plaintext, List<String> recipients, int permissions, String expiresAt)
        throws IOException, InterruptedException, CustodiaHttpError {
        String normalizedSecretId = requireText(secretId, "secret id");
        ParsedSecret currentSecret = ParsedSecret.parse(transport.getSecretPayload(normalizedSecretId));
        CustodiaCrypto.AADInputs currentAADInputs = currentSecret.metadata().canonicalAADInputs(
            new CustodiaCrypto.AADInputs(currentSecret.namespace(), currentSecret.key(), 1)
        );
        CustodiaCrypto.AADInputs aadInputs = new CustodiaCrypto.AADInputs(
            currentAADInputs.namespace(), currentAADInputs.key(), currentAADInputs.secretVersion() + 1
        );
        byte[] dek = random(CustodiaCrypto.AES256_GCM_KEY_BYTES);
        byte[] nonce = random(CustodiaCrypto.AES_GCM_NONCE_BYTES);
        CustodiaCrypto.CryptoMetadata metadata = CustodiaCrypto.metadataV1(aadInputs, nonce);
        byte[] aad = CustodiaCrypto.buildCanonicalAAD(metadata, aadInputs);
        byte[] ciphertext = CustodiaCrypto.sealContentAES256GCM(dek, nonce, plaintext, aad);

        StringBuilder payload = new StringBuilder();
        payload.append('{');
        appendField(payload, "ciphertext", CustodiaCrypto.encodeBase64(ciphertext));
        payload.append(',');
        payload.append(CustodiaCrypto.quote("crypto_metadata")).append(':').append(CustodiaCrypto.metadataJson(metadata));
        payload.append(',');
        payload.append(CustodiaCrypto.quote("envelopes")).append(':').append(sealRecipientEnvelopes(normalizedRecipients(recipients), dek, aad));
        payload.append(',');
        payload.append(CustodiaCrypto.quote("permissions")).append(':').append(permissions);
        if (expiresAt != null && !expiresAt.isBlank()) {
            payload.append(',');
            appendField(payload, "expires_at", expiresAt);
        }
        payload.append('}');
        return transport.createSecretVersionPayload(normalizedSecretId, payload.toString());
    }

    public String createEncryptedSecretVersionByKey(String namespace, String key, byte[] plaintext, List<String> recipients, int permissions)
        throws IOException, InterruptedException, CustodiaHttpError {
        return createEncryptedSecretVersionByKey(namespace, key, plaintext, recipients, permissions, null);
    }

    public String createEncryptedSecretVersionByKey(
        String namespace,
        String key,
        byte[] plaintext,
        List<String> recipients,
        int permissions,
        String expiresAt
    ) throws IOException, InterruptedException, CustodiaHttpError {
        String normalizedNamespace = requireText(namespace, "namespace");
        String normalizedKey = requireText(key, "secret key");
        ParsedSecret currentSecret = ParsedSecret.parse(transport.getSecretPayloadByKey(normalizedNamespace, normalizedKey));
        CustodiaCrypto.AADInputs currentAADInputs = currentSecret.metadata().canonicalAADInputs(
            new CustodiaCrypto.AADInputs(normalizedNamespace, normalizedKey, 1)
        );
        CustodiaCrypto.AADInputs aadInputs = new CustodiaCrypto.AADInputs(
            currentAADInputs.namespace(), currentAADInputs.key(), currentAADInputs.secretVersion() + 1
        );
        byte[] dek = random(CustodiaCrypto.AES256_GCM_KEY_BYTES);
        byte[] nonce = random(CustodiaCrypto.AES_GCM_NONCE_BYTES);
        CustodiaCrypto.CryptoMetadata metadata = CustodiaCrypto.metadataV1(aadInputs, nonce);
        byte[] aad = CustodiaCrypto.buildCanonicalAAD(metadata, aadInputs);
        byte[] ciphertext = CustodiaCrypto.sealContentAES256GCM(dek, nonce, plaintext, aad);

        StringBuilder payload = new StringBuilder();
        payload.append('{');
        appendField(payload, "ciphertext", CustodiaCrypto.encodeBase64(ciphertext));
        payload.append(',');
        payload.append(CustodiaCrypto.quote("crypto_metadata")).append(':').append(CustodiaCrypto.metadataJson(metadata));
        payload.append(',');
        payload.append(CustodiaCrypto.quote("envelopes")).append(':').append(sealRecipientEnvelopes(normalizedRecipients(recipients), dek, aad));
        payload.append(',');
        payload.append(CustodiaCrypto.quote("permissions")).append(':').append(permissions);
        if (expiresAt != null && !expiresAt.isBlank()) {
            payload.append(',');
            appendField(payload, "expires_at", expiresAt);
        }
        payload.append('}');
        return transport.createSecretVersionPayloadByKey(normalizedNamespace, normalizedKey, payload.toString());
    }

    public DecryptedSecret readDecryptedSecret(String secretId) throws IOException, InterruptedException, CustodiaHttpError {
        String payload = transport.getSecretPayload(secretId);
        ParsedSecret secret = ParsedSecret.parse(payload);
        CustodiaCrypto.CryptoMetadata metadata = secret.metadata();
        CustodiaCrypto.AADInputs fallback = new CustodiaCrypto.AADInputs(secret.namespace(), secret.key(), 1);
        CustodiaCrypto.AADInputs aadInputs = metadata.canonicalAADInputs(fallback);
        byte[] aad = CustodiaCrypto.buildCanonicalAAD(metadata, aadInputs);
        if (metadata.contentNonceB64().isBlank()) {
            throw new CustodiaCrypto.MalformedCryptoMetadataException("missing content nonce");
        }
        byte[] nonce = CustodiaCrypto.decodeBase64(metadata.contentNonceB64());
        byte[] dek = openSecretEnvelope(secret.envelope(), aad);
        byte[] plaintext = CustodiaCrypto.openContentAES256GCM(dek, nonce, CustodiaCrypto.decodeBase64(secret.ciphertext()), aad);
        return new DecryptedSecret(secret.secretId(), secret.versionId(), plaintext, metadata, secret.permissions(), secret.grantedAt(), secret.accessExpiresAt());
    }

    public DecryptedSecret readDecryptedSecretByKey(String namespace, String key) throws IOException, InterruptedException, CustodiaHttpError {
        String payload = transport.getSecretPayloadByKey(namespace, key);
        ParsedSecret secret = ParsedSecret.parse(payload);
        CustodiaCrypto.CryptoMetadata metadata = secret.metadata();
        CustodiaCrypto.AADInputs fallback = new CustodiaCrypto.AADInputs(secret.namespace(), secret.key(), 1);
        CustodiaCrypto.AADInputs aadInputs = metadata.canonicalAADInputs(fallback);
        byte[] aad = CustodiaCrypto.buildCanonicalAAD(metadata, aadInputs);
        if (metadata.contentNonceB64().isBlank()) {
            throw new CustodiaCrypto.MalformedCryptoMetadataException("missing content nonce");
        }
        byte[] nonce = CustodiaCrypto.decodeBase64(metadata.contentNonceB64());
        byte[] dek = openSecretEnvelope(secret.envelope(), aad);
        byte[] plaintext = CustodiaCrypto.openContentAES256GCM(dek, nonce, CustodiaCrypto.decodeBase64(secret.ciphertext()), aad);
        return new DecryptedSecret(secret.secretId(), secret.versionId(), plaintext, metadata, secret.permissions(), secret.grantedAt(), secret.accessExpiresAt());
    }

    public String shareEncryptedSecret(String secretId, String targetClientId, int permissions)
        throws IOException, InterruptedException, CustodiaHttpError {
        return shareEncryptedSecret(secretId, targetClientId, permissions, null);
    }

    public String shareEncryptedSecret(String secretId, String targetClientId, int permissions, String expiresAt)
        throws IOException, InterruptedException, CustodiaHttpError {
        String normalizedTarget = requireText(targetClientId, "target client id");
        String payload = transport.getSecretPayload(secretId);
        ParsedSecret secret = ParsedSecret.parse(payload);
        CustodiaCrypto.CryptoMetadata metadata = secret.metadata();
        CustodiaCrypto.AADInputs fallback = new CustodiaCrypto.AADInputs(secret.namespace(), secret.key(), 1);
        CustodiaCrypto.AADInputs aadInputs = metadata.canonicalAADInputs(fallback);
        byte[] aad = CustodiaCrypto.buildCanonicalAAD(metadata, aadInputs);
        byte[] dek = openSecretEnvelope(secret.envelope(), aad);
        String envelope = sealRecipientEnvelopes(List.of(normalizedTarget), dek, aad);
        String envelopeObject = envelope.substring(1, envelope.length() - 1);

        StringBuilder request = new StringBuilder();
        request.append('{');
        appendField(request, "version_id", secret.versionId());
        request.append(',');
        appendField(request, "target_client_id", normalizedTarget);
        request.append(',');
        request.append(envelopeObject.replaceFirst("^\\\"client_id\\\":\\\"[^\\\"]+\\\",", ""));
        request.append(',');
        request.append(CustodiaCrypto.quote("permissions")).append(':').append(permissions);
        if (expiresAt != null && !expiresAt.isBlank()) {
            request.append(',');
            appendField(request, "expires_at", expiresAt);
        }
        request.append('}');
        return transport.shareSecretPayload(secretId, request.toString());
    }

    public String shareEncryptedSecretByKey(String namespace, String key, String targetClientId, int permissions)
        throws IOException, InterruptedException, CustodiaHttpError {
        return shareEncryptedSecretByKey(namespace, key, targetClientId, permissions, null);
    }

    public String shareEncryptedSecretByKey(String namespace, String key, String targetClientId, int permissions, String expiresAt)
        throws IOException, InterruptedException, CustodiaHttpError {
        String normalizedNamespace = requireText(namespace, "namespace");
        String normalizedKey = requireText(key, "secret key");
        String normalizedTarget = requireText(targetClientId, "target client id");
        String payload = transport.getSecretPayloadByKey(normalizedNamespace, normalizedKey);
        ParsedSecret secret = ParsedSecret.parse(payload);
        CustodiaCrypto.CryptoMetadata metadata = secret.metadata();
        CustodiaCrypto.AADInputs fallback = new CustodiaCrypto.AADInputs(secret.namespace(), secret.key(), 1);
        CustodiaCrypto.AADInputs aadInputs = metadata.canonicalAADInputs(fallback);
        byte[] aad = CustodiaCrypto.buildCanonicalAAD(metadata, aadInputs);
        byte[] dek = openSecretEnvelope(secret.envelope(), aad);
        String envelope = sealRecipientEnvelopes(List.of(normalizedTarget), dek, aad);
        String envelopeObject = envelope.substring(1, envelope.length() - 1);

        StringBuilder request = new StringBuilder();
        request.append('{');
        appendField(request, "version_id", secret.versionId());
        request.append(',');
        appendField(request, "target_client_id", normalizedTarget);
        request.append(',');
        request.append(envelopeObject.replaceFirst("^\"client_id\":\"[^\"]+\",", ""));
        request.append(',');
        request.append(CustodiaCrypto.quote("permissions")).append(':').append(permissions);
        if (expiresAt != null && !expiresAt.isBlank()) {
            request.append(',');
            appendField(request, "expires_at", expiresAt);
        }
        request.append('}');
        return transport.shareSecretPayloadByKey(normalizedNamespace, normalizedKey, request.toString());
    }

    private List<String> normalizedRecipients(List<String> recipients) {
        CustodiaCrypto.X25519PrivateKeyHandle current = options.privateKeyProvider().currentPrivateKey();
        Set<String> normalized = new LinkedHashSet<>();
        if (current.clientId() != null && !current.clientId().isBlank()) {
            normalized.add(current.clientId());
        }
        if (recipients != null) {
            for (String recipient : recipients) {
                if (recipient != null && !recipient.isBlank()) {
                    normalized.add(recipient.trim());
                }
            }
        }
        if (normalized.isEmpty()) {
            throw new IllegalArgumentException("missing recipient envelope");
        }
        return new ArrayList<>(normalized);
    }

    private String sealRecipientEnvelopes(List<String> recipients, byte[] dek, byte[] aad) {
        StringBuilder envelopes = new StringBuilder();
        envelopes.append('[');
        for (int i = 0; i < recipients.size(); i++) {
            if (i > 0) {
                envelopes.append(',');
            }
            String recipientId = recipients.get(i);
            CustodiaCrypto.RecipientPublicKey recipient = options.publicKeyResolver().resolveRecipientPublicKey(recipientId);
            if (!CustodiaCrypto.ENVELOPE_SCHEME_HPKE_V1.equals(recipient.scheme())) {
                throw new CustodiaCrypto.UnsupportedEnvelopeSchemeException("unsupported envelope scheme");
            }
            byte[] envelope = CustodiaCrypto.sealHPKEV1Envelope(recipient.publicKey(), random(CustodiaCrypto.X25519_KEY_BYTES), dek, aad);
            envelopes.append('{');
            appendField(envelopes, "client_id", recipientId);
            envelopes.append(',');
            appendField(envelopes, "envelope", CustodiaCrypto.encodeBase64(envelope));
            envelopes.append('}');
        }
        envelopes.append(']');
        return envelopes.toString();
    }

    private byte[] openSecretEnvelope(String encodedEnvelope, byte[] aad) {
        CustodiaCrypto.X25519PrivateKeyHandle privateKey = options.privateKeyProvider().currentPrivateKey();
        if (!CustodiaCrypto.ENVELOPE_SCHEME_HPKE_V1.equals(privateKey.scheme())) {
            throw new CustodiaCrypto.UnsupportedEnvelopeSchemeException("unsupported envelope scheme");
        }
        return privateKey.openEnvelope(CustodiaCrypto.decodeBase64(encodedEnvelope), aad);
    }

    private byte[] random(int length) {
        byte[] value = options.randomSource().randomBytes(length);
        if (value == null || value.length != length) {
            throw new IllegalArgumentException("random source returned invalid length");
        }
        return value;
    }

    private static String requireText(String value, String label) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(label + " is required");
        }
        return value.trim();
    }

    private static void appendField(StringBuilder json, String key, String value) {
        json.append(CustodiaCrypto.quote(key)).append(':').append(CustodiaCrypto.quote(value));
    }

    public record DecryptedSecret(
        String secretId,
        String versionId,
        byte[] plaintext,
        CustodiaCrypto.CryptoMetadata cryptoMetadata,
        int permissions,
        String grantedAt,
        String accessExpiresAt
    ) {
        public String plaintextUtf8() {
            return new String(plaintext, StandardCharsets.UTF_8);
        }
    }

    private record ParsedSecret(
        String secretId,
        String namespace,
        String key,
        String versionId,
        String ciphertext,
        CustodiaCrypto.CryptoMetadata metadata,
        String envelope,
        int permissions,
        String grantedAt,
        String accessExpiresAt
    ) {
        static ParsedSecret parse(String json) {
            String metadataObject = objectField(json, "crypto_metadata");
            CustodiaCrypto.AADInputs aad = null;
            String aadObject = objectField(metadataObject, "aad");
            if (!aadObject.isBlank()) {
                aad = new CustodiaCrypto.AADInputs(
                    stringField(aadObject, "namespace"),
                    stringField(aadObject, "key"),
                    intField(aadObject, "secret_version")
                );
            }
            CustodiaCrypto.CryptoMetadata metadata = new CustodiaCrypto.CryptoMetadata(
                stringField(metadataObject, "version"),
                stringField(metadataObject, "content_cipher"),
                stringField(metadataObject, "envelope_scheme"),
                stringField(metadataObject, "content_nonce_b64"),
                aad
            );
            CustodiaCrypto.validateMetadata(metadata);
            return new ParsedSecret(
                stringField(json, "secret_id"),
                stringField(json, "namespace"),
                stringField(json, "key"),
                stringField(json, "version_id"),
                stringField(json, "ciphertext"),
                metadata,
                stringField(json, "envelope"),
                intField(json, "permissions"),
                stringField(json, "granted_at"),
                stringField(json, "access_expires_at")
            );
        }
    }

    private static String stringField(String json, String field) {
        String needle = CustodiaCrypto.quote(field) + ':';
        int index = json.indexOf(needle);
        if (index < 0) {
            return "";
        }
        int start = json.indexOf('"', index + needle.length());
        if (start < 0) {
            return "";
        }
        StringBuilder out = new StringBuilder();
        boolean escaped = false;
        for (int i = start + 1; i < json.length(); i++) {
            char ch = json.charAt(i);
            if (escaped) {
                out.append(switch (ch) {
                    case '"' -> '"';
                    case '\\' -> '\\';
                    case 'b' -> '\b';
                    case 'f' -> '\f';
                    case 'n' -> '\n';
                    case 'r' -> '\r';
                    case 't' -> '\t';
                    default -> ch;
                });
                escaped = false;
            } else if (ch == '\\') {
                escaped = true;
            } else if (ch == '"') {
                return out.toString();
            } else {
                out.append(ch);
            }
        }
        return "";
    }

    private static int intField(String json, String field) {
        String needle = CustodiaCrypto.quote(field) + ':';
        int index = json.indexOf(needle);
        if (index < 0) {
            return 0;
        }
        int start = index + needle.length();
        while (start < json.length() && Character.isWhitespace(json.charAt(start))) {
            start++;
        }
        int end = start;
        while (end < json.length() && Character.isDigit(json.charAt(end))) {
            end++;
        }
        if (end == start) {
            return 0;
        }
        try {
            return Integer.parseInt(json.substring(start, end));
        } catch (NumberFormatException err) {
            throw new IllegalArgumentException("integer field is out of range: " + field, err);
        }
    }

    private static String objectField(String json, String field) {
        String needle = CustodiaCrypto.quote(field) + ':';
        int index = json.indexOf(needle);
        if (index < 0) {
            return "";
        }
        int start = json.indexOf('{', index + needle.length());
        if (start < 0) {
            return "";
        }
        int depth = 0;
        boolean inString = false;
        boolean escaped = false;
        for (int i = start; i < json.length(); i++) {
            char ch = json.charAt(i);
            if (inString) {
                if (escaped) {
                    escaped = false;
                } else if (ch == '\\') {
                    escaped = true;
                } else if (ch == '"') {
                    inString = false;
                }
                continue;
            }
            if (ch == '"') {
                inString = true;
            } else if (ch == '{') {
                depth++;
            } else if (ch == '}') {
                depth--;
                if (depth == 0) {
                    return json.substring(start, i + 1);
                }
            }
        }
        return "";
    }
}
