import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  randomBytes,
} from "node:crypto";

export const CryptoVersionV1 = "custodia.client-crypto.v1";
export const ContentCipherV1 = "aes-256-gcm";
export const EnvelopeSchemeHPKEV1 = "hpke-v1";
export const AES256GCMKeyBytes = 32;
export const AESGCMNonceBytes = 12;
export const AESGCMTagBytes = 16;
export const X25519KeyBytes = 32;

const HPKE_ENVELOPE_INFO = Buffer.from("custodia.client-crypto.v1 envelope", "utf8");
const HPKE_KEM_ID = Buffer.from([0x00, 0x20]);
const HPKE_KDF_ID = Buffer.from([0x00, 0x01]);
const HPKE_AEAD_ID = Buffer.from([0x00, 0x02]);
const HPKE_KEM_SUITE_ID = Buffer.concat([Buffer.from("KEM", "utf8"), HPKE_KEM_ID]);
const HPKE_SUITE_ID = Buffer.concat([Buffer.from("HPKE", "utf8"), HPKE_KEM_ID, HPKE_KDF_ID, HPKE_AEAD_ID]);
const HPKE_VERSION_LABEL = Buffer.from("HPKE-v1", "utf8");
const X25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b656e04220420", "hex");
const X25519_SPKI_PREFIX = Buffer.from("302a300506032b656e032100", "hex");

export class CryptoError extends Error {
  constructor(message) {
    super(message);
    this.name = new.target.name;
  }
}

export class UnsupportedCryptoVersion extends CryptoError {}
export class UnsupportedContentCipher extends CryptoError {}
export class UnsupportedEnvelopeScheme extends CryptoError {}
export class MalformedCryptoMetadata extends CryptoError {}
export class MalformedAAD extends CryptoError {}
export class CiphertextAuthenticationFailed extends CryptoError {}
export class WrongRecipient extends CryptoError {}

export class CanonicalAADInputs {
  constructor({ secretID = "", secretName = "", versionID = "" } = {}) {
    this.secretID = secretID;
    this.secretName = secretName;
    this.versionID = versionID;
  }

  static fromMapping(value) {
    if (!value) {
      return new CanonicalAADInputs();
    }
    return new CanonicalAADInputs({
      secretID: String(value.secret_id ?? value.secretID ?? ""),
      secretName: String(value.secret_name ?? value.secretName ?? ""),
      versionID: String(value.version_id ?? value.versionID ?? ""),
    });
  }

  toMetadataObject() {
    const payload = {};
    if (this.secretID) {
      payload.secret_id = this.secretID;
    }
    if (this.secretName) {
      payload.secret_name = this.secretName;
    }
    if (this.versionID) {
      payload.version_id = this.versionID;
    }
    return payload;
  }
}

export class CryptoMetadata {
  constructor({
    version = CryptoVersionV1,
    contentCipher = ContentCipherV1,
    envelopeScheme = EnvelopeSchemeHPKEV1,
    contentNonceB64 = "",
    aad = null,
  } = {}) {
    this.version = version;
    this.contentCipher = contentCipher;
    this.envelopeScheme = envelopeScheme;
    this.contentNonceB64 = contentNonceB64;
    this.aad = aad;
  }

  static fromMapping(payload) {
    if (payload == null || typeof payload !== "object") {
      throw new MalformedCryptoMetadata("malformed crypto metadata");
    }
    return new CryptoMetadata({
      version: String(payload.version ?? ""),
      contentCipher: String(payload.content_cipher ?? payload.contentCipher ?? ""),
      envelopeScheme: String(payload.envelope_scheme ?? payload.envelopeScheme ?? ""),
      contentNonceB64: String(payload.content_nonce_b64 ?? payload.contentNonceB64 ?? ""),
      aad: payload.aad == null ? null : CanonicalAADInputs.fromMapping(payload.aad),
    });
  }

  toJSON() {
    const payload = {
      version: this.version,
      content_cipher: this.contentCipher,
      envelope_scheme: this.envelopeScheme,
    };
    if (this.contentNonceB64) {
      payload.content_nonce_b64 = this.contentNonceB64;
    }
    if (this.aad) {
      payload.aad = this.aad.toMetadataObject();
    }
    return payload;
  }

  canonicalAADInputs(fallback) {
    return this.aad ?? fallback;
  }
}

export function metadataV1(aad, contentNonce) {
  return new CryptoMetadata({ contentNonceB64: encodeBase64(contentNonce), aad });
}

export function parseMetadata(payload) {
  let value = payload;
  if (Buffer.isBuffer(payload)) {
    value = payload.toString("utf8");
  }
  if (typeof value === "string") {
    try {
      value = JSON.parse(value);
    } catch (error) {
      throw new MalformedCryptoMetadata("malformed crypto metadata", { cause: error });
    }
  }
  const metadata = CryptoMetadata.fromMapping(value);
  validateMetadata(metadata);
  return metadata;
}

export function validateMetadata(metadata) {
  if (metadata.version !== CryptoVersionV1) {
    throw new UnsupportedCryptoVersion("unsupported crypto metadata version");
  }
  if (metadata.contentCipher !== ContentCipherV1) {
    throw new UnsupportedContentCipher("unsupported content cipher");
  }
  if (metadata.envelopeScheme !== EnvelopeSchemeHPKEV1) {
    throw new UnsupportedEnvelopeScheme("unsupported envelope scheme");
  }
}

export function buildCanonicalAAD(metadata, inputs) {
  if (!(metadata instanceof CryptoMetadata)) {
    metadata = CryptoMetadata.fromMapping(metadata);
  }
  validateMetadata(metadata);
  if (!inputs.secretID && !inputs.secretName) {
    throw new MalformedAAD("secret_id or secret_name is required");
  }
  const document = {
    version: metadata.version,
    content_cipher: metadata.contentCipher,
    envelope_scheme: metadata.envelopeScheme,
  };
  if (inputs.secretID) {
    document.secret_id = inputs.secretID;
  }
  if (inputs.secretName) {
    document.secret_name = inputs.secretName;
  }
  if (inputs.versionID) {
    document.version_id = inputs.versionID;
  }
  return Buffer.from(JSON.stringify(document), "utf8");
}

export function canonicalAADSHA256(aad) {
  return createHash("sha256").update(aad).digest("hex");
}

export function sealContentAES256GCM(key, nonce, plaintext, aad) {
  assertLength(key, AES256GCMKeyBytes, "invalid content key");
  assertLength(nonce, AESGCMNonceBytes, "invalid content nonce");
  const cipher = createCipheriv("aes-256-gcm", Buffer.from(key), Buffer.from(nonce));
  cipher.setAAD(Buffer.from(aad));
  const encrypted = Buffer.concat([cipher.update(Buffer.from(plaintext)), cipher.final()]);
  return Buffer.concat([encrypted, cipher.getAuthTag()]);
}

export function openContentAES256GCM(key, nonce, ciphertext, aad) {
  assertLength(key, AES256GCMKeyBytes, "invalid content key");
  assertLength(nonce, AESGCMNonceBytes, "invalid content nonce");
  const payload = Buffer.from(ciphertext);
  if (payload.length <= AESGCMTagBytes) {
    throw new CiphertextAuthenticationFailed("ciphertext authentication failed");
  }
  const encrypted = payload.subarray(0, payload.length - AESGCMTagBytes);
  const tag = payload.subarray(payload.length - AESGCMTagBytes);
  try {
    const decipher = createDecipheriv("aes-256-gcm", Buffer.from(key), Buffer.from(nonce));
    decipher.setAAD(Buffer.from(aad));
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(encrypted), decipher.final()]);
  } catch (error) {
    throw new CiphertextAuthenticationFailed("ciphertext authentication failed", { cause: error });
  }
}

export function deriveX25519PublicKey(privateKey) {
  const publicKey = createPublicKey(x25519PrivateKeyObject(privateKey));
  return rawX25519PublicKey(publicKey);
}

export function sealHPKEV1Envelope(recipientPublicKey, senderEphemeralPrivateKey, dek, aad) {
  assertLength(recipientPublicKey, X25519KeyBytes, "invalid envelope key");
  assertLength(senderEphemeralPrivateKey, X25519KeyBytes, "invalid envelope key");
  const skE = x25519PrivateKeyObject(senderEphemeralPrivateKey);
  const pkR = x25519PublicKeyObject(recipientPublicKey);
  const enc = deriveX25519PublicKey(senderEphemeralPrivateKey);
  const dh = diffieHellman({ privateKey: skE, publicKey: pkR });
  const sharedSecret = hpkeKEMExtractAndExpand(dh, Buffer.concat([enc, Buffer.from(recipientPublicKey)]));
  const sealed = hpkeSeal(sharedSecret, HPKE_ENVELOPE_INFO, dek, aad);
  return Buffer.concat([enc, sealed]);
}

export function openHPKEV1Envelope(recipientPrivateKey, envelope, aad) {
  assertLength(recipientPrivateKey, X25519KeyBytes, "invalid envelope key");
  const payload = Buffer.from(envelope);
  if (payload.length <= X25519KeyBytes + AESGCMTagBytes) {
    throw new MalformedCryptoMetadata("malformed envelope");
  }
  const skR = x25519PrivateKeyObject(recipientPrivateKey);
  const pkE = x25519PublicKeyObject(payload.subarray(0, X25519KeyBytes));
  const recipientPublicKey = deriveX25519PublicKey(recipientPrivateKey);
  const dh = diffieHellman({ privateKey: skR, publicKey: pkE });
  const sharedSecret = hpkeKEMExtractAndExpand(dh, Buffer.concat([payload.subarray(0, X25519KeyBytes), recipientPublicKey]));
  try {
    return hpkeOpen(sharedSecret, HPKE_ENVELOPE_INFO, payload.subarray(X25519KeyBytes), aad);
  } catch (error) {
    throw new WrongRecipient("wrong recipient", { cause: error });
  }
}

export function encodeEnvelope(envelope) {
  return encodeBase64(envelope);
}

export function decodeEnvelope(value) {
  try {
    return Buffer.from(value, "base64");
  } catch (error) {
    throw new MalformedCryptoMetadata("malformed envelope", { cause: error });
  }
}

export class RecipientPublicKey {
  constructor({ clientID, scheme = EnvelopeSchemeHPKEV1, publicKey, fingerprint = "" }) {
    this.clientID = clientID;
    this.scheme = scheme;
    this.publicKey = Buffer.from(publicKey);
    this.fingerprint = fingerprint;
  }
}

export class X25519PrivateKeyHandle {
  constructor({ clientID, privateKey }) {
    this.clientID = clientID;
    this.privateKey = Buffer.from(privateKey);
    deriveX25519PublicKey(this.privateKey);
  }

  get scheme() {
    return EnvelopeSchemeHPKEV1;
  }

  openEnvelope(envelope, aad) {
    return openHPKEV1Envelope(this.privateKey, envelope, aad);
  }
}

export function deriveX25519RecipientPublicKey(clientID, privateKey) {
  return new RecipientPublicKey({ clientID, publicKey: deriveX25519PublicKey(privateKey) });
}

export class StaticPrivateKeyProvider {
  constructor(privateKey) {
    this.privateKey = privateKey;
  }

  currentPrivateKey() {
    return this.privateKey;
  }
}

export class StaticPublicKeyResolver {
  constructor(publicKeys) {
    this.publicKeys = new Map(Object.entries(publicKeys));
  }

  resolveRecipientPublicKey(clientID) {
    const publicKey = this.publicKeys.get(clientID);
    if (!publicKey) {
      throw new Error(`missing recipient public key: ${clientID}`);
    }
    return publicKey;
  }
}

export class CryptoOptions {
  constructor({ publicKeyResolver, privateKeyProvider, randomSource = randomBytes }) {
    this.publicKeyResolver = publicKeyResolver;
    this.privateKeyProvider = privateKeyProvider;
    this.randomSource = randomSource;
  }

  validate() {
    if (!this.publicKeyResolver) {
      throw new TypeError("public key resolver is required");
    }
    if (!this.privateKeyProvider) {
      throw new TypeError("private key provider is required");
    }
    if (!this.randomSource) {
      throw new TypeError("random source is required");
    }
  }
}

export class DecryptedSecret {
  constructor({ secretID, versionID, plaintext, cryptoMetadata, permissions, grantedAt = "", accessExpiresAt = null }) {
    this.secretID = secretID;
    this.versionID = versionID;
    this.plaintext = Buffer.from(plaintext);
    this.cryptoMetadata = cryptoMetadata;
    this.permissions = permissions;
    this.grantedAt = grantedAt;
    this.accessExpiresAt = accessExpiresAt;
  }
}

export class CryptoCustodiaClient {
  constructor(transport, options) {
    this.transport = transport;
    this.options = options;
    this.options.validate();
  }

  async createEncryptedSecret({ name, plaintext, recipients = [], permissions = 7, expiresAt } = {}) {
    if (!String(name ?? "").trim()) {
      throw new TypeError("secret name is required");
    }
    const dek = this.random(AES256GCMKeyBytes);
    const nonce = this.random(AESGCMNonceBytes);
    const aadInputs = new CanonicalAADInputs({ secretName: name });
    const metadata = metadataV1(aadInputs, nonce);
    const aad = buildCanonicalAAD(metadata, aadInputs);
    const ciphertext = sealContentAES256GCM(dek, nonce, Buffer.from(plaintext), aad);
    const payload = {
      name,
      ciphertext: encodeBase64(ciphertext),
      crypto_metadata: metadata.toJSON(),
      envelopes: this.sealRecipientEnvelopes(this.normalizedRecipients(recipients), dek, aad),
      permissions,
    };
    if (expiresAt) {
      payload.expires_at = expiresAt;
    }
    return this.transport.createSecretPayload(payload);
  }

  async createEncryptedSecretVersion({ secretID, plaintext, recipients = [], permissions = 7, expiresAt } = {}) {
    if (!String(secretID ?? "").trim()) {
      throw new TypeError("secret id is required");
    }
    const dek = this.random(AES256GCMKeyBytes);
    const nonce = this.random(AESGCMNonceBytes);
    const aadInputs = new CanonicalAADInputs({ secretID });
    const metadata = metadataV1(aadInputs, nonce);
    const aad = buildCanonicalAAD(metadata, aadInputs);
    const ciphertext = sealContentAES256GCM(dek, nonce, Buffer.from(plaintext), aad);
    const payload = {
      ciphertext: encodeBase64(ciphertext),
      crypto_metadata: metadata.toJSON(),
      envelopes: this.sealRecipientEnvelopes(this.normalizedRecipients(recipients), dek, aad),
      permissions,
    };
    if (expiresAt) {
      payload.expires_at = expiresAt;
    }
    return this.transport.createSecretVersionPayload(secretID, payload);
  }

  async readDecryptedSecret(secretID) {
    const secret = await this.transport.getSecretPayload(secretID);
    const metadata = parseMetadata(secret.crypto_metadata ?? {});
    const fallback = new CanonicalAADInputs({
      secretID: String(secret.secret_id ?? ""),
      versionID: String(secret.version_id ?? ""),
    });
    const aadInputs = metadata.canonicalAADInputs(fallback);
    const aad = buildCanonicalAAD(metadata, aadInputs);
    if (!metadata.contentNonceB64) {
      throw new MalformedCryptoMetadata("missing content nonce");
    }
    const nonce = decodeBase64(metadata.contentNonceB64);
    const dek = this.openSecretEnvelope(String(secret.envelope ?? ""), aad);
    const ciphertext = decodeBase64(String(secret.ciphertext ?? ""));
    const plaintext = openContentAES256GCM(dek, nonce, ciphertext, aad);
    return new DecryptedSecret({
      secretID: String(secret.secret_id ?? ""),
      versionID: String(secret.version_id ?? ""),
      plaintext,
      cryptoMetadata: metadata.toJSON(),
      permissions: Number(secret.permissions ?? 0),
      grantedAt: String(secret.granted_at ?? ""),
      accessExpiresAt: secret.access_expires_at ?? null,
    });
  }

  async shareEncryptedSecret({ secretID, targetClientID, permissions = 4, expiresAt } = {}) {
    if (!String(targetClientID ?? "").trim()) {
      throw new TypeError("target client id is required");
    }
    const secret = await this.transport.getSecretPayload(secretID);
    const metadata = parseMetadata(secret.crypto_metadata ?? {});
    const fallback = new CanonicalAADInputs({
      secretID: String(secret.secret_id ?? ""),
      versionID: String(secret.version_id ?? ""),
    });
    const aadInputs = metadata.canonicalAADInputs(fallback);
    const aad = buildCanonicalAAD(metadata, aadInputs);
    const dek = this.openSecretEnvelope(String(secret.envelope ?? ""), aad);
    const envelope = this.sealRecipientEnvelopes([targetClientID], dek, aad)[0];
    const payload = {
      version_id: String(secret.version_id ?? ""),
      target_client_id: targetClientID,
      envelope: envelope.envelope,
      permissions,
    };
    if (expiresAt) {
      payload.expires_at = expiresAt;
    }
    return this.transport.shareSecretPayload(secretID, payload);
  }

  normalizedRecipients(recipients) {
    const current = this.options.privateKeyProvider.currentPrivateKey();
    const normalized = [];
    const seen = new Set();
    if (current.clientID) {
      normalized.push(current.clientID);
      seen.add(current.clientID);
    }
    for (const recipient of recipients) {
      const value = String(recipient ?? "").trim();
      if (value && !seen.has(value)) {
        normalized.push(value);
        seen.add(value);
      }
    }
    if (normalized.length === 0) {
      throw new TypeError("missing recipient envelope");
    }
    return normalized;
  }

  sealRecipientEnvelopes(recipients, dek, aad) {
    return recipients.map((recipientID) => {
      const publicKey = this.options.publicKeyResolver.resolveRecipientPublicKey(recipientID);
      if (publicKey.scheme !== EnvelopeSchemeHPKEV1) {
        throw new UnsupportedEnvelopeScheme("unsupported envelope scheme");
      }
      const envelope = sealHPKEV1Envelope(publicKey.publicKey, this.random(X25519KeyBytes), dek, aad);
      return { client_id: recipientID, envelope: encodeEnvelope(envelope) };
    });
  }

  openSecretEnvelope(encodedEnvelope, aad) {
    const privateKey = this.options.privateKeyProvider.currentPrivateKey();
    if (privateKey.scheme !== EnvelopeSchemeHPKEV1) {
      throw new UnsupportedEnvelopeScheme("unsupported envelope scheme");
    }
    return privateKey.openEnvelope(decodeEnvelope(encodedEnvelope), aad);
  }

  random(length) {
    const value = Buffer.from(this.options.randomSource(length));
    if (value.length !== length) {
      throw new TypeError("random source returned invalid length");
    }
    return value;
  }
}

export function withCrypto(client, options) {
  return new CryptoCustodiaClient(client, options);
}

function hpkeSeal(sharedSecret, info, plaintext, aad) {
  const { key, nonce } = hpkeKeySchedule(sharedSecret, info);
  return sealContentAES256GCM(key, nonce, plaintext, aad);
}

function hpkeOpen(sharedSecret, info, ciphertext, aad) {
  const { key, nonce } = hpkeKeySchedule(sharedSecret, info);
  return openContentAES256GCM(key, nonce, ciphertext, aad);
}

function hpkeKeySchedule(sharedSecret, info) {
  const pskIDHash = hpkeLabeledExtract(HPKE_SUITE_ID, null, Buffer.from("psk_id_hash", "utf8"), Buffer.alloc(0));
  const infoHash = hpkeLabeledExtract(HPKE_SUITE_ID, null, Buffer.from("info_hash", "utf8"), info);
  const context = Buffer.concat([Buffer.from([0x00]), pskIDHash, infoHash]);
  const secret = hpkeLabeledExtract(HPKE_SUITE_ID, sharedSecret, Buffer.from("secret", "utf8"), Buffer.alloc(0));
  return {
    key: hpkeLabeledExpand(secret, HPKE_SUITE_ID, Buffer.from("key", "utf8"), context, AES256GCMKeyBytes),
    nonce: hpkeLabeledExpand(secret, HPKE_SUITE_ID, Buffer.from("base_nonce", "utf8"), context, AESGCMNonceBytes),
  };
}

function hpkeKEMExtractAndExpand(dh, kemContext) {
  const eaePRK = hpkeLabeledExtract(HPKE_KEM_SUITE_ID, null, Buffer.from("eae_prk", "utf8"), dh);
  return hpkeLabeledExpand(eaePRK, HPKE_KEM_SUITE_ID, Buffer.from("shared_secret", "utf8"), kemContext, 32);
}

function hpkeLabeledExtract(suiteID, salt, label, ikm) {
  return hkdfExtract(salt, Buffer.concat([HPKE_VERSION_LABEL, suiteID, label, Buffer.from(ikm)]));
}

function hpkeLabeledExpand(prk, suiteID, label, info, length) {
  const lengthPrefix = Buffer.alloc(2);
  lengthPrefix.writeUInt16BE(length, 0);
  const labeledInfo = Buffer.concat([lengthPrefix, HPKE_VERSION_LABEL, suiteID, label, Buffer.from(info)]);
  return hkdfExpand(prk, labeledInfo, length);
}

function hkdfExtract(salt, ikm) {
  return createHmac("sha256", salt ?? Buffer.alloc(32)).update(ikm).digest();
}

function hkdfExpand(prk, info, length) {
  let result = Buffer.alloc(0);
  let previous = Buffer.alloc(0);
  let counter = 1;
  while (result.length < length) {
    previous = createHmac("sha256", prk).update(Buffer.concat([previous, info, Buffer.from([counter])])).digest();
    result = Buffer.concat([result, previous]);
    counter += 1;
  }
  return result.subarray(0, length);
}

function x25519PrivateKeyObject(rawPrivateKey) {
  assertLength(rawPrivateKey, X25519KeyBytes, "invalid x25519 private key");
  return createPrivateKey({ key: Buffer.concat([X25519_PKCS8_PREFIX, Buffer.from(rawPrivateKey)]), format: "der", type: "pkcs8" });
}

function x25519PublicKeyObject(rawPublicKey) {
  assertLength(rawPublicKey, X25519KeyBytes, "invalid x25519 public key");
  return createPublicKey({ key: Buffer.concat([X25519_SPKI_PREFIX, Buffer.from(rawPublicKey)]), format: "der", type: "spki" });
}

function rawX25519PublicKey(publicKey) {
  const der = publicKey.export({ format: "der", type: "spki" });
  return der.subarray(der.length - X25519KeyBytes);
}

function assertLength(value, length, message) {
  if (Buffer.from(value).length !== length) {
    throw new MalformedCryptoMetadata(message);
  }
}

function encodeBase64(value) {
  return Buffer.from(value).toString("base64");
}

function decodeBase64(value) {
  return Buffer.from(value, "base64");
}
