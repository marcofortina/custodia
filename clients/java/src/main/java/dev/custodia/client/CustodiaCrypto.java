/*
 * Copyright (c) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * This file is part of Custodia.
 * Custodia is distributed under the GNU Affero General Public License v3.0.
 * See the accompanying LICENSE file for details.
 */

package dev.custodia.client;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Local-only crypto primitives shared by the Java high-level client.
 *
 * The implementation intentionally mirrors the common test vectors instead of
 * relying on server-side crypto negotiation; unsupported metadata versions must
 * fail closed before plaintext is released.
 */
public final class CustodiaCrypto {
    public static final String CRYPTO_VERSION_V1 = "custodia.client-crypto.v1";
    public static final String CONTENT_CIPHER_V1 = "aes-256-gcm";
    public static final String ENVELOPE_SCHEME_HPKE_V1 = "hpke-v1";
    public static final int AES256_GCM_KEY_BYTES = 32;
    public static final int AES_GCM_NONCE_BYTES = 12;
    public static final int AES_GCM_TAG_BYTES = 16;
    public static final int X25519_KEY_BYTES = 32;

    private static final byte[] HPKE_ENVELOPE_INFO = "custodia.client-crypto.v1 envelope".getBytes(StandardCharsets.UTF_8);
    private static final byte[] HPKE_KEM_ID = new byte[] {0x00, 0x20};
    private static final byte[] HPKE_KDF_ID = new byte[] {0x00, 0x01};
    private static final byte[] HPKE_AEAD_ID = new byte[] {0x00, 0x02};
    private static final byte[] HPKE_KEM_SUITE_ID = concat("KEM".getBytes(StandardCharsets.UTF_8), HPKE_KEM_ID);
    private static final byte[] HPKE_SUITE_ID = concat("HPKE".getBytes(StandardCharsets.UTF_8), HPKE_KEM_ID, HPKE_KDF_ID, HPKE_AEAD_ID);
    private static final byte[] HPKE_VERSION_LABEL = "HPKE-v1".getBytes(StandardCharsets.UTF_8);
    private static final byte[] X25519_PKCS8_PREFIX = hex("302e020100300506032b656e04220420");
    private static final byte[] X25519_SPKI_PREFIX = hex("302a300506032b656e032100");

    private CustodiaCrypto() {}

    public static byte[] buildCanonicalAAD(CryptoMetadata metadata, AADInputs inputs) {
        validateMetadata(metadata);
        if (inputs.namespace() == null || inputs.namespace().isBlank()
            || inputs.key() == null || inputs.key().isBlank()
            || inputs.secretVersion() <= 0) {
            throw new MalformedAADException("namespace, key and secret_version are required");
        }
        StringBuilder json = new StringBuilder();
        json.append('{');
        appendJsonField(json, "version", metadata.version());
        json.append(',');
        appendJsonField(json, "content_cipher", metadata.contentCipher());
        json.append(',');
        appendJsonField(json, "envelope_scheme", metadata.envelopeScheme());
        json.append(',');
        appendJsonField(json, "namespace", inputs.namespace());
        json.append(',');
        appendJsonField(json, "key", inputs.key());
        json.append(',');
        json.append(quote("secret_version")).append(':').append(inputs.secretVersion());
        json.append('}');
        return json.toString().getBytes(StandardCharsets.UTF_8);
    }

    public static String canonicalAADSHA256(byte[] aad) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(aad);
            StringBuilder out = new StringBuilder(digest.length * 2);
            for (byte value : digest) {
                out.append(String.format("%02x", value & 0xff));
            }
            return out.toString();
        } catch (GeneralSecurityException err) {
            throw new CryptoException("sha256 unavailable", err);
        }
    }

    public static CryptoMetadata metadataV1(AADInputs aad, byte[] contentNonce) {
        return new CryptoMetadata(CRYPTO_VERSION_V1, CONTENT_CIPHER_V1, ENVELOPE_SCHEME_HPKE_V1, encodeBase64(contentNonce), aad);
    }

    public static void validateMetadata(CryptoMetadata metadata) {
        if (!CRYPTO_VERSION_V1.equals(metadata.version())) {
            throw new UnsupportedCryptoVersionException("unsupported crypto metadata version");
        }
        if (!CONTENT_CIPHER_V1.equals(metadata.contentCipher())) {
            throw new UnsupportedContentCipherException("unsupported content cipher");
        }
        if (!ENVELOPE_SCHEME_HPKE_V1.equals(metadata.envelopeScheme())) {
            throw new UnsupportedEnvelopeSchemeException("unsupported envelope scheme");
        }
    }

    public static ContentCiphertext sealContentAES256GCM(byte[] key, byte[] plaintext, byte[] aad, RandomSource randomSource) {
        Objects.requireNonNull(randomSource, "randomSource");
        assertLength(key, AES256_GCM_KEY_BYTES, "invalid content key");
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new RandomSourceSecureRandom(randomSource));
            byte[] nonce = cipher.getIV();
            assertLength(nonce, AES_GCM_NONCE_BYTES, "invalid content nonce");
            cipher.updateAAD(aad);
            return new ContentCiphertext(nonce, cipher.doFinal(plaintext));
        } catch (GeneralSecurityException err) {
            throw new CryptoException("content encryption failed", err);
        }
    }

    // HPKE derives this AEAD nonce from the per-recipient key schedule. Do not use this helper for content encryption.
    private static byte[] sealHPKEEnvelopeAES256GCM(byte[] key, byte[] nonce, byte[] plaintext, byte[] aad) {
        assertLength(key, AES256_GCM_KEY_BYTES, "invalid HPKE envelope key");
        assertLength(nonce, AES_GCM_NONCE_BYTES, "invalid HPKE envelope nonce");
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            // lgtm[java/static-initialization-vector] HPKE AEAD nonces are deterministically derived from a fresh ephemeral shared secret.
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(AES_GCM_TAG_BYTES * 8, nonce));
            cipher.updateAAD(aad);
            return cipher.doFinal(plaintext);
        } catch (GeneralSecurityException err) {
            throw new CryptoException("HPKE envelope encryption failed", err);
        }
    }

    public static byte[] openContentAES256GCM(byte[] key, byte[] nonce, byte[] ciphertext, byte[] aad) {
        assertLength(key, AES256_GCM_KEY_BYTES, "invalid content key");
        assertLength(nonce, AES_GCM_NONCE_BYTES, "invalid content nonce");
        if (ciphertext.length <= AES_GCM_TAG_BYTES) {
            throw new CiphertextAuthenticationFailedException("ciphertext authentication failed");
        }
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(AES_GCM_TAG_BYTES * 8, nonce));
            cipher.updateAAD(aad);
            return cipher.doFinal(ciphertext);
        } catch (GeneralSecurityException err) {
            throw new CiphertextAuthenticationFailedException("ciphertext authentication failed", err);
        }
    }

    public static byte[] deriveX25519PublicKey(byte[] privateKey) {
        assertLength(privateKey, X25519_KEY_BYTES, "invalid x25519 private key");
        byte[] basePoint = new byte[X25519_KEY_BYTES];
        basePoint[0] = 9;
        return x25519(privateKey, basePoint);
    }

    public static byte[] sealHPKEV1Envelope(byte[] recipientPublicKey, byte[] senderEphemeralPrivateKey, byte[] dek, byte[] aad) {
        assertLength(recipientPublicKey, X25519_KEY_BYTES, "invalid envelope key");
        assertLength(senderEphemeralPrivateKey, X25519_KEY_BYTES, "invalid envelope key");
        byte[] enc = deriveX25519PublicKey(senderEphemeralPrivateKey);
        byte[] dh = x25519(senderEphemeralPrivateKey, recipientPublicKey);
        byte[] sharedSecret = hpkeKEMExtractAndExpand(dh, concat(enc, recipientPublicKey));
        byte[] sealed = hpkeSeal(sharedSecret, HPKE_ENVELOPE_INFO, dek, aad);
        return concat(enc, sealed);
    }

    public static byte[] openHPKEV1Envelope(byte[] recipientPrivateKey, byte[] envelope, byte[] aad) {
        assertLength(recipientPrivateKey, X25519_KEY_BYTES, "invalid envelope key");
        if (envelope.length <= X25519_KEY_BYTES + AES_GCM_TAG_BYTES) {
            throw new MalformedCryptoMetadataException("malformed envelope");
        }
        byte[] enc = Arrays.copyOfRange(envelope, 0, X25519_KEY_BYTES);
        byte[] ciphertext = Arrays.copyOfRange(envelope, X25519_KEY_BYTES, envelope.length);
        byte[] recipientPublicKey = deriveX25519PublicKey(recipientPrivateKey);
        byte[] dh = x25519(recipientPrivateKey, enc);
        byte[] sharedSecret = hpkeKEMExtractAndExpand(dh, concat(enc, recipientPublicKey));
        try {
            return hpkeOpen(sharedSecret, HPKE_ENVELOPE_INFO, ciphertext, aad);
        } catch (CiphertextAuthenticationFailedException err) {
            throw new WrongRecipientException("wrong recipient", err);
        }
    }

    public static RecipientPublicKey deriveX25519RecipientPublicKey(String clientId, byte[] privateKey) {
        return new RecipientPublicKey(clientId, ENVELOPE_SCHEME_HPKE_V1, deriveX25519PublicKey(privateKey), "");
    }

    public static String encodeBase64(byte[] value) {
        return java.util.Base64.getEncoder().encodeToString(value);
    }

    public static byte[] decodeBase64(String value) {
        return java.util.Base64.getDecoder().decode(value);
    }

    static String quote(String value) {
        return '"' + escapeJson(value) + '"';
    }

    static String metadataJson(CryptoMetadata metadata) {
        StringBuilder json = new StringBuilder();
        json.append('{');
        appendJsonField(json, "version", metadata.version());
        json.append(',');
        appendJsonField(json, "content_cipher", metadata.contentCipher());
        json.append(',');
        appendJsonField(json, "envelope_scheme", metadata.envelopeScheme());
        if (metadata.contentNonceB64() != null && !metadata.contentNonceB64().isBlank()) {
            json.append(',');
            appendJsonField(json, "content_nonce_b64", metadata.contentNonceB64());
        }
        if (metadata.aad() != null) {
            json.append(',');
            json.append(quote("aad")).append(':').append(aadJson(metadata.aad()));
        }
        json.append('}');
        return json.toString();
    }

    static String aadJson(AADInputs aad) {
        StringBuilder json = new StringBuilder();
        json.append('{');
        appendJsonField(json, "namespace", aad.namespace());
        json.append(',');
        appendJsonField(json, "key", aad.key());
        json.append(',');
        json.append(quote("secret_version")).append(':').append(aad.secretVersion());
        json.append('}');
        return json.toString();
    }

    static String escapeJson(String value) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            switch (ch) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\b' -> out.append("\\b");
                case '\f' -> out.append("\\f");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (ch < 0x20) {
                        out.append(String.format("\\u%04x", (int) ch));
                    } else {
                        out.append(ch);
                    }
                }
            }
        }
        return out.toString();
    }

    private static byte[] hpkeSeal(byte[] sharedSecret, byte[] info, byte[] plaintext, byte[] aad) {
        HPKEKeySchedule schedule = hpkeKeySchedule(sharedSecret, info);
        return sealHPKEEnvelopeAES256GCM(schedule.key(), schedule.nonce(), plaintext, aad);
    }

    private static byte[] hpkeOpen(byte[] sharedSecret, byte[] info, byte[] ciphertext, byte[] aad) {
        HPKEKeySchedule schedule = hpkeKeySchedule(sharedSecret, info);
        return openContentAES256GCM(schedule.key(), schedule.nonce(), ciphertext, aad);
    }

    private static HPKEKeySchedule hpkeKeySchedule(byte[] sharedSecret, byte[] info) {
        byte[] pskIDHash = hpkeLabeledExtract(HPKE_SUITE_ID, null, "psk_id_hash".getBytes(StandardCharsets.UTF_8), new byte[0]);
        byte[] infoHash = hpkeLabeledExtract(HPKE_SUITE_ID, null, "info_hash".getBytes(StandardCharsets.UTF_8), info);
        byte[] context = concat(new byte[] {0x00}, pskIDHash, infoHash);
        byte[] secret = hpkeLabeledExtract(HPKE_SUITE_ID, sharedSecret, "secret".getBytes(StandardCharsets.UTF_8), new byte[0]);
        return new HPKEKeySchedule(
            hpkeLabeledExpand(secret, HPKE_SUITE_ID, "key".getBytes(StandardCharsets.UTF_8), context, AES256_GCM_KEY_BYTES),
            hpkeLabeledExpand(secret, HPKE_SUITE_ID, "base_nonce".getBytes(StandardCharsets.UTF_8), context, AES_GCM_NONCE_BYTES)
        );
    }

    private static byte[] hpkeKEMExtractAndExpand(byte[] dh, byte[] kemContext) {
        byte[] eaePRK = hpkeLabeledExtract(HPKE_KEM_SUITE_ID, null, "eae_prk".getBytes(StandardCharsets.UTF_8), dh);
        return hpkeLabeledExpand(eaePRK, HPKE_KEM_SUITE_ID, "shared_secret".getBytes(StandardCharsets.UTF_8), kemContext, 32);
    }

    private static byte[] hpkeLabeledExtract(byte[] suiteID, byte[] salt, byte[] label, byte[] ikm) {
        return hkdfExtract(salt, concat(HPKE_VERSION_LABEL, suiteID, label, ikm));
    }

    private static byte[] hpkeLabeledExpand(byte[] prk, byte[] suiteID, byte[] label, byte[] info, int length) {
        ByteBuffer lengthPrefix = ByteBuffer.allocate(2).putShort((short) length);
        byte[] labeledInfo = concat(lengthPrefix.array(), HPKE_VERSION_LABEL, suiteID, label, info);
        return hkdfExpand(prk, labeledInfo, length);
    }

    private static byte[] hkdfExtract(byte[] salt, byte[] ikm) {
        return hmacSha256(salt == null ? new byte[32] : salt, ikm);
    }

    private static byte[] hkdfExpand(byte[] prk, byte[] info, int length) {
        byte[] result = new byte[0];
        byte[] previous = new byte[0];
        int counter = 1;
        while (result.length < length) {
            previous = hmacSha256(prk, concat(previous, info, new byte[] {(byte) counter}));
            result = concat(result, previous);
            counter++;
        }
        return Arrays.copyOf(result, length);
    }

    private static byte[] hmacSha256(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (GeneralSecurityException err) {
            throw new CryptoException("hmac-sha256 unavailable", err);
        }
    }

    private static byte[] x25519(byte[] privateKey, byte[] publicKey) {
        try {
            KeyAgreement agreement = KeyAgreement.getInstance("XDH");
            agreement.init(x25519PrivateKey(privateKey));
            agreement.doPhase(x25519PublicKey(publicKey), true);
            return agreement.generateSecret();
        } catch (GeneralSecurityException err) {
            throw new CryptoException("x25519 operation failed", err);
        }
    }

    private static PrivateKey x25519PrivateKey(byte[] rawPrivateKey) throws GeneralSecurityException {
        return KeyFactory.getInstance("XDH").generatePrivate(new PKCS8EncodedKeySpec(concat(X25519_PKCS8_PREFIX, rawPrivateKey)));
    }

    private static PublicKey x25519PublicKey(byte[] rawPublicKey) throws GeneralSecurityException {
        return KeyFactory.getInstance("XDH").generatePublic(new X509EncodedKeySpec(concat(X25519_SPKI_PREFIX, rawPublicKey)));
    }

    private static void appendJsonField(StringBuilder json, String key, String value) {
        json.append(quote(key)).append(':').append(quote(value));
    }

    private static void assertLength(byte[] value, int length, String message) {
        if (value == null || value.length != length) {
            throw new MalformedCryptoMetadataException(message);
        }
    }

    private static byte[] concat(byte[]... values) {
        int size = 0;
        for (byte[] value : values) {
            size += value.length;
        }
        byte[] out = new byte[size];
        int offset = 0;
        for (byte[] value : values) {
            System.arraycopy(value, 0, out, offset, value.length);
            offset += value.length;
        }
        return out;
    }

    private static byte[] hex(String value) {
        if (value.length() % 2 != 0) {
            throw new IllegalArgumentException("hex value must have an even length");
        }
        byte[] out = new byte[value.length() / 2];
        try {
            for (int i = 0; i < out.length; i++) {
                out[i] = (byte) Integer.parseInt(value.substring(i * 2, i * 2 + 2), 16);
            }
        } catch (NumberFormatException err) {
            throw new IllegalArgumentException("hex value must contain only hexadecimal characters", err);
        }
        return out;
    }

    private record HPKEKeySchedule(byte[] key, byte[] nonce) {}

    public record AADInputs(String namespace, String key, int secretVersion) {
        public AADInputs {
            namespace = namespace == null ? "" : namespace;
            key = key == null ? "" : key;
        }
    }

    public record ContentCiphertext(byte[] nonce, byte[] ciphertext) {
        public ContentCiphertext {
            nonce = Arrays.copyOf(Objects.requireNonNull(nonce, "nonce"), nonce.length);
            ciphertext = Arrays.copyOf(Objects.requireNonNull(ciphertext, "ciphertext"), ciphertext.length);
        }

        @Override
        public byte[] nonce() { return Arrays.copyOf(nonce, nonce.length); }

        @Override
        public byte[] ciphertext() { return Arrays.copyOf(ciphertext, ciphertext.length); }
    }

    public record CryptoMetadata(String version, String contentCipher, String envelopeScheme, String contentNonceB64, AADInputs aad) {
        public CryptoMetadata {
            version = version == null ? "" : version;
            contentCipher = contentCipher == null ? "" : contentCipher;
            envelopeScheme = envelopeScheme == null ? "" : envelopeScheme;
            contentNonceB64 = contentNonceB64 == null ? "" : contentNonceB64;
        }

        public AADInputs canonicalAADInputs(AADInputs fallback) {
            return aad == null ? fallback : aad;
        }
    }

    public static final class RecipientPublicKey {
        private final String clientId;
        private final String scheme;
        private final byte[] publicKey;
        private final String fingerprint;

        public RecipientPublicKey(String clientId, String scheme, byte[] publicKey, String fingerprint) {
            this.clientId = Objects.requireNonNull(clientId, "clientId");
            this.scheme = scheme == null || scheme.isBlank() ? ENVELOPE_SCHEME_HPKE_V1 : scheme;
            this.publicKey = Arrays.copyOf(Objects.requireNonNull(publicKey, "publicKey"), publicKey.length);
            this.fingerprint = fingerprint == null ? "" : fingerprint;
        }

        public String clientId() { return clientId; }
        public String scheme() { return scheme; }
        public byte[] publicKey() { return Arrays.copyOf(publicKey, publicKey.length); }
        public String fingerprint() { return fingerprint; }
    }

    public interface PublicKeyResolver {
        RecipientPublicKey resolveRecipientPublicKey(String clientId);
    }

    public interface PrivateKeyProvider {
        X25519PrivateKeyHandle currentPrivateKey();
    }

    public interface RandomSource {
        byte[] randomBytes(int length);
    }

    public static final class SecureRandomSource implements RandomSource {
        private final SecureRandom secureRandom = new SecureRandom();

        @Override
        public byte[] randomBytes(int length) {
            byte[] out = new byte[length];
            secureRandom.nextBytes(out);
            return out;
        }
    }

    private static final class RandomSourceSecureRandom extends SecureRandom {
        private final transient RandomSource randomSource;

        RandomSourceSecureRandom(RandomSource randomSource) {
            this.randomSource = Objects.requireNonNull(randomSource, "randomSource");
        }

        @Override
        public void nextBytes(byte[] bytes) {
            byte[] generated = randomSource.randomBytes(bytes.length);
            if (generated.length != bytes.length) {
                throw new CryptoException("invalid generated content nonce length");
            }
            System.arraycopy(generated, 0, bytes, 0, bytes.length);
        }
    }

    public static final class StaticPublicKeyResolver implements PublicKeyResolver {
        private final Map<String, RecipientPublicKey> recipients;

        public StaticPublicKeyResolver(Map<String, RecipientPublicKey> recipients) {
            this.recipients = new LinkedHashMap<>(Objects.requireNonNull(recipients, "recipients"));
        }

        @Override
        public RecipientPublicKey resolveRecipientPublicKey(String clientId) {
            RecipientPublicKey recipient = recipients.get(clientId);
            if (recipient == null) {
                throw new CryptoException("recipient public key not found");
            }
            return recipient;
        }
    }

    public static final class StaticPrivateKeyProvider implements PrivateKeyProvider {
        private final X25519PrivateKeyHandle privateKey;

        public StaticPrivateKeyProvider(X25519PrivateKeyHandle privateKey) {
            this.privateKey = Objects.requireNonNull(privateKey, "privateKey");
        }

        @Override
        public X25519PrivateKeyHandle currentPrivateKey() {
            return privateKey;
        }
    }

    public static final class X25519PrivateKeyHandle {
        private final String clientId;
        private final byte[] privateKey;

        public X25519PrivateKeyHandle(String clientId, byte[] privateKey) {
            this.clientId = clientId == null ? "" : clientId;
            this.privateKey = Arrays.copyOf(Objects.requireNonNull(privateKey, "privateKey"), privateKey.length);
            deriveX25519PublicKey(this.privateKey);
        }

        public String clientId() { return clientId; }
        public String scheme() { return ENVELOPE_SCHEME_HPKE_V1; }
        public byte[] openEnvelope(byte[] envelope, byte[] aad) { return openHPKEV1Envelope(privateKey, envelope, aad); }
        public byte[] privateKey() { return Arrays.copyOf(privateKey, privateKey.length); }
    }

    public static final class CryptoOptions {
        private final PublicKeyResolver publicKeyResolver;
        private final PrivateKeyProvider privateKeyProvider;
        private final RandomSource randomSource;

        public CryptoOptions(PublicKeyResolver publicKeyResolver, PrivateKeyProvider privateKeyProvider, RandomSource randomSource) {
            this.publicKeyResolver = Objects.requireNonNull(publicKeyResolver, "publicKeyResolver");
            this.privateKeyProvider = Objects.requireNonNull(privateKeyProvider, "privateKeyProvider");
            this.randomSource = randomSource == null ? new SecureRandomSource() : randomSource;
        }

        public PublicKeyResolver publicKeyResolver() { return publicKeyResolver; }
        public PrivateKeyProvider privateKeyProvider() { return privateKeyProvider; }
        public RandomSource randomSource() { return randomSource; }
    }

    public static class CryptoException extends RuntimeException {
        public CryptoException(String message) { super(message); }
        public CryptoException(String message, Throwable cause) { super(message, cause); }
    }

    public static final class UnsupportedCryptoVersionException extends CryptoException {
        public UnsupportedCryptoVersionException(String message) { super(message); }
    }

    public static final class UnsupportedContentCipherException extends CryptoException {
        public UnsupportedContentCipherException(String message) { super(message); }
    }

    public static final class UnsupportedEnvelopeSchemeException extends CryptoException {
        public UnsupportedEnvelopeSchemeException(String message) { super(message); }
    }

    public static final class MalformedCryptoMetadataException extends CryptoException {
        public MalformedCryptoMetadataException(String message) { super(message); }
    }

    public static final class MalformedAADException extends CryptoException {
        public MalformedAADException(String message) { super(message); }
    }

    public static final class CiphertextAuthenticationFailedException extends CryptoException {
        public CiphertextAuthenticationFailedException(String message) { super(message); }
        public CiphertextAuthenticationFailedException(String message, Throwable cause) { super(message, cause); }
    }

    public static final class WrongRecipientException extends CryptoException {
        public WrongRecipientException(String message, Throwable cause) { super(message, cause); }
    }
}
