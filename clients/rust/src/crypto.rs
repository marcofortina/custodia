/*
 * Copyright (c) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * This file is part of Custodia.
 * Custodia is distributed under the GNU Affero General Public License v3.0.
 * See the accompanying LICENSE file for details.
 */

//! Shared Rust client-side crypto helpers for Custodia high-level SDK flows.
//!
//! These helpers implement the same v1 contract used by the Go, Python,
//! Node.js, Java and C++ clients: canonical AAD, AES-256-GCM content crypto
//! and HPKE-v1 recipient envelopes. The server never receives plaintext, DEKs
//! or private keys.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use x25519_dalek::{PublicKey, StaticSecret};

pub const CRYPTO_VERSION_V1: &str = "custodia.client-crypto.v1";
pub const CONTENT_CIPHER_V1: &str = "aes-256-gcm";
pub const ENVELOPE_SCHEME_HPKE_V1: &str = "hpke-v1";
pub const AES_256_GCM_KEY_BYTES: usize = 32;
pub const AES_GCM_NONCE_BYTES: usize = 12;
pub const AES_GCM_TAG_BYTES: usize = 16;
pub const X25519_KEY_BYTES: usize = 32;

const HPKE_ENVELOPE_INFO: &[u8] = b"custodia.client-crypto.v1 envelope";
const HPKE_KEM_ID: &[u8] = b"\x00\x20";
const HPKE_KDF_ID: &[u8] = b"\x00\x01";
const HPKE_AEAD_ID: &[u8] = b"\x00\x02";
const HPKE_VERSION_LABEL: &[u8] = b"HPKE-v1";

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum CryptoError {
    UnsupportedCryptoVersion,
    UnsupportedContentCipher,
    UnsupportedEnvelopeScheme,
    MalformedCryptoMetadata(String),
    MalformedAAD,
    CiphertextAuthenticationFailed,
    WrongRecipient,
    RandomSource(String),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedCryptoVersion => write!(f, "unsupported crypto metadata version"),
            Self::UnsupportedContentCipher => write!(f, "unsupported content cipher"),
            Self::UnsupportedEnvelopeScheme => write!(f, "unsupported envelope scheme"),
            Self::MalformedCryptoMetadata(message) => write!(f, "malformed crypto metadata: {message}"),
            Self::MalformedAAD => write!(f, "malformed crypto aad"),
            Self::CiphertextAuthenticationFailed => write!(f, "ciphertext authentication failed"),
            Self::WrongRecipient => write!(f, "wrong recipient"),
            Self::RandomSource(message) => write!(f, "random source error: {message}"),
        }
    }
}

impl std::error::Error for CryptoError {}

pub type CryptoResult<T> = std::result::Result<T, CryptoError>;

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct CanonicalAADInputs {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub secret_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub secret_name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub version_id: String,
}

impl CanonicalAADInputs {
    pub fn from_value(value: Option<&Value>) -> Self {
        let Some(Value::Object(map)) = value else {
            return Self::default();
        };
        Self {
            secret_id: string_field(map.get("secret_id")).unwrap_or_default(),
            secret_name: string_field(map.get("secret_name")).unwrap_or_default(),
            version_id: string_field(map.get("version_id")).unwrap_or_default(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CryptoMetadata {
    pub version: String,
    pub content_cipher: String,
    pub envelope_scheme: String,
    pub content_nonce_b64: String,
    pub aad: Option<CanonicalAADInputs>,
}

impl CryptoMetadata {
    pub fn to_value(&self) -> Value {
        let mut payload = serde_json::Map::new();
        payload.insert("version".to_string(), Value::String(self.version.clone()));
        payload.insert("content_cipher".to_string(), Value::String(self.content_cipher.clone()));
        payload.insert("envelope_scheme".to_string(), Value::String(self.envelope_scheme.clone()));
        if !self.content_nonce_b64.is_empty() {
            payload.insert("content_nonce_b64".to_string(), Value::String(self.content_nonce_b64.clone()));
        }
        if let Some(aad) = &self.aad {
            payload.insert(
                "aad".to_string(),
                serde_json::to_value(aad).unwrap_or_else(|_| Value::Object(Default::default())),
            );
        }
        Value::Object(payload)
    }

    pub fn canonical_aad_inputs(&self, fallback: CanonicalAADInputs) -> CanonicalAADInputs {
        self.aad.clone().unwrap_or(fallback)
    }
}

#[derive(Serialize)]
struct CanonicalAADDocument<'a> {
    version: &'a str,
    content_cipher: &'a str,
    envelope_scheme: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    secret_id: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    secret_name: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    version_id: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecipientPublicKey {
    pub client_id: String,
    pub scheme: String,
    pub public_key: Vec<u8>,
    pub fingerprint: String,
}

pub trait PublicKeyResolver: Send + Sync {
    fn resolve_recipient_public_key(&self, client_id: &str) -> CryptoResult<RecipientPublicKey>;
}

pub trait PrivateKeyHandle: Send + Sync {
    fn client_id(&self) -> &str;
    fn scheme(&self) -> &str;
    fn open_envelope(&self, envelope: &[u8], aad: &[u8]) -> CryptoResult<Vec<u8>>;
}

pub trait PrivateKeyProvider: Send + Sync {
    fn current_private_key(&self) -> CryptoResult<Arc<dyn PrivateKeyHandle>>;
}

pub trait RandomSource: Send + Sync {
    fn random(&self, length: usize) -> CryptoResult<Vec<u8>>;
}

#[derive(Default)]
pub struct OsRandomSource;

impl RandomSource for OsRandomSource {
    fn random(&self, length: usize) -> CryptoResult<Vec<u8>> {
        let mut value = vec![0_u8; length];
        OsRng.fill_bytes(&mut value);
        Ok(value)
    }
}

pub struct CryptoOptions {
    pub public_key_resolver: Arc<dyn PublicKeyResolver>,
    pub private_key_provider: Arc<dyn PrivateKeyProvider>,
    pub random_source: Arc<dyn RandomSource>,
}

impl CryptoOptions {
    pub fn new(
        public_key_resolver: Arc<dyn PublicKeyResolver>,
        private_key_provider: Arc<dyn PrivateKeyProvider>,
    ) -> Self {
        Self {
            public_key_resolver,
            private_key_provider,
            random_source: Arc::new(OsRandomSource),
        }
    }

    pub fn with_random_source(mut self, random_source: Arc<dyn RandomSource>) -> Self {
        self.random_source = random_source;
        self
    }
}

#[derive(Clone)]
pub struct X25519PrivateKeyHandle {
    client_id: String,
    private_key: [u8; X25519_KEY_BYTES],
}

impl X25519PrivateKeyHandle {
    pub fn new(client_id: impl Into<String>, private_key: &[u8]) -> CryptoResult<Self> {
        Ok(Self {
            client_id: client_id.into(),
            private_key: fixed_32(private_key, "invalid x25519 private key")?,
        })
    }

    pub fn public_key(&self) -> Vec<u8> {
        derive_x25519_public_key(&self.private_key).unwrap_or_default()
    }
}

impl PrivateKeyHandle for X25519PrivateKeyHandle {
    fn client_id(&self) -> &str {
        &self.client_id
    }

    fn scheme(&self) -> &str {
        ENVELOPE_SCHEME_HPKE_V1
    }

    fn open_envelope(&self, envelope: &[u8], aad: &[u8]) -> CryptoResult<Vec<u8>> {
        open_hpke_v1_envelope(&self.private_key, envelope, aad)
    }
}

pub struct StaticPrivateKeyProvider {
    private_key: Arc<dyn PrivateKeyHandle>,
}

impl StaticPrivateKeyProvider {
    pub fn new(private_key: Arc<dyn PrivateKeyHandle>) -> Self {
        Self { private_key }
    }
}

impl PrivateKeyProvider for StaticPrivateKeyProvider {
    fn current_private_key(&self) -> CryptoResult<Arc<dyn PrivateKeyHandle>> {
        Ok(self.private_key.clone())
    }
}

#[derive(Clone, Default)]
pub struct StaticPublicKeyResolver {
    public_keys: BTreeMap<String, RecipientPublicKey>,
}

impl StaticPublicKeyResolver {
    pub fn new(public_keys: BTreeMap<String, RecipientPublicKey>) -> Self {
        Self { public_keys }
    }
}

impl PublicKeyResolver for StaticPublicKeyResolver {
    fn resolve_recipient_public_key(&self, client_id: &str) -> CryptoResult<RecipientPublicKey> {
        self.public_keys
            .get(client_id)
            .cloned()
            .ok_or_else(|| CryptoError::MalformedCryptoMetadata(format!("missing recipient public key: {client_id}")))
    }
}

pub fn metadata_v1(aad: CanonicalAADInputs, content_nonce: &[u8]) -> CryptoMetadata {
    CryptoMetadata {
        version: CRYPTO_VERSION_V1.to_string(),
        content_cipher: CONTENT_CIPHER_V1.to_string(),
        envelope_scheme: ENVELOPE_SCHEME_HPKE_V1.to_string(),
        content_nonce_b64: encode_base64(content_nonce),
        aad: Some(aad),
    }
}

pub fn parse_metadata(payload: &Value) -> CryptoResult<CryptoMetadata> {
    let Value::Object(map) = payload else {
        return Err(CryptoError::MalformedCryptoMetadata("metadata object is required".to_string()));
    };
    let metadata = CryptoMetadata {
        version: string_field(map.get("version")).unwrap_or_default(),
        content_cipher: string_field(map.get("content_cipher")).unwrap_or_default(),
        envelope_scheme: string_field(map.get("envelope_scheme")).unwrap_or_default(),
        content_nonce_b64: string_field(map.get("content_nonce_b64")).unwrap_or_default(),
        aad: map.get("aad").map(|value| CanonicalAADInputs::from_value(Some(value))),
    };
    validate_metadata(&metadata)?;
    Ok(metadata)
}

pub fn validate_metadata(metadata: &CryptoMetadata) -> CryptoResult<()> {
    if metadata.version != CRYPTO_VERSION_V1 {
        return Err(CryptoError::UnsupportedCryptoVersion);
    }
    if metadata.content_cipher != CONTENT_CIPHER_V1 {
        return Err(CryptoError::UnsupportedContentCipher);
    }
    if metadata.envelope_scheme != ENVELOPE_SCHEME_HPKE_V1 {
        return Err(CryptoError::UnsupportedEnvelopeScheme);
    }
    Ok(())
}

pub fn build_canonical_aad(metadata: &CryptoMetadata, inputs: &CanonicalAADInputs) -> CryptoResult<Vec<u8>> {
    validate_metadata(metadata)?;
    if inputs.secret_id.is_empty() && inputs.secret_name.is_empty() {
        return Err(CryptoError::MalformedAAD);
    }
    serde_json::to_vec(&CanonicalAADDocument {
        version: &metadata.version,
        content_cipher: &metadata.content_cipher,
        envelope_scheme: &metadata.envelope_scheme,
        secret_id: &inputs.secret_id,
        secret_name: &inputs.secret_name,
        version_id: &inputs.version_id,
    })
    .map_err(|err| CryptoError::MalformedCryptoMetadata(err.to_string()))
}

pub fn canonical_aad_sha256(aad: &[u8]) -> String {
    let digest = Sha256::digest(aad);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn seal_content_aes_256_gcm(key: &[u8], nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> CryptoResult<Vec<u8>> {
    if key.len() != AES_256_GCM_KEY_BYTES {
        return Err(CryptoError::MalformedCryptoMetadata("invalid content key".to_string()));
    }
    if nonce.len() != AES_GCM_NONCE_BYTES {
        return Err(CryptoError::MalformedCryptoMetadata("invalid content nonce".to_string()));
    }
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|err| CryptoError::MalformedCryptoMetadata(err.to_string()))?;
    cipher
        .encrypt(Nonce::from_slice(nonce), Payload { msg: plaintext, aad })
        .map_err(|_| CryptoError::CiphertextAuthenticationFailed)
}

pub fn open_content_aes_256_gcm(key: &[u8], nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> CryptoResult<Vec<u8>> {
    if key.len() != AES_256_GCM_KEY_BYTES {
        return Err(CryptoError::MalformedCryptoMetadata("invalid content key".to_string()));
    }
    if nonce.len() != AES_GCM_NONCE_BYTES {
        return Err(CryptoError::MalformedCryptoMetadata("invalid content nonce".to_string()));
    }
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|err| CryptoError::MalformedCryptoMetadata(err.to_string()))?;
    cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ciphertext, aad })
        .map_err(|_| CryptoError::CiphertextAuthenticationFailed)
}

pub fn derive_x25519_public_key(private_key: &[u8]) -> CryptoResult<Vec<u8>> {
    let secret = StaticSecret::from(fixed_32(private_key, "invalid x25519 private key")?);
    Ok(PublicKey::from(&secret).as_bytes().to_vec())
}

pub fn derive_x25519_recipient_public_key(client_id: impl Into<String>, private_key: &[u8]) -> CryptoResult<RecipientPublicKey> {
    Ok(RecipientPublicKey {
        client_id: client_id.into(),
        scheme: ENVELOPE_SCHEME_HPKE_V1.to_string(),
        public_key: derive_x25519_public_key(private_key)?,
        fingerprint: String::new(),
    })
}

pub fn seal_hpke_v1_envelope(
    recipient_public_key: &[u8],
    sender_ephemeral_private_key: &[u8],
    dek: &[u8],
    aad: &[u8],
) -> CryptoResult<Vec<u8>> {
    let pk_r = PublicKey::from(fixed_32(recipient_public_key, "invalid envelope key")?);
    let sk_e = StaticSecret::from(fixed_32(sender_ephemeral_private_key, "invalid envelope key")?);
    let enc = PublicKey::from(&sk_e);
    let dh = sk_e.diffie_hellman(&pk_r);
    let mut kem_context = enc.as_bytes().to_vec();
    kem_context.extend_from_slice(pk_r.as_bytes());
    let shared_secret = hpke_kem_extract_and_expand(dh.as_bytes(), &kem_context);
    let sealed = hpke_seal(&shared_secret, HPKE_ENVELOPE_INFO, dek, aad)?;
    let mut envelope = enc.as_bytes().to_vec();
    envelope.extend_from_slice(&sealed);
    Ok(envelope)
}

pub fn open_hpke_v1_envelope(recipient_private_key: &[u8], envelope: &[u8], aad: &[u8]) -> CryptoResult<Vec<u8>> {
    if envelope.len() <= X25519_KEY_BYTES + AES_GCM_TAG_BYTES {
        return Err(CryptoError::MalformedCryptoMetadata("malformed envelope".to_string()));
    }
    let sk_r = StaticSecret::from(fixed_32(recipient_private_key, "invalid envelope key")?);
    let pk_e = PublicKey::from(fixed_32(&envelope[..X25519_KEY_BYTES], "malformed envelope")?);
    let recipient_public_key = PublicKey::from(&sk_r);
    let dh = sk_r.diffie_hellman(&pk_e);
    let mut kem_context = pk_e.as_bytes().to_vec();
    kem_context.extend_from_slice(recipient_public_key.as_bytes());
    let shared_secret = hpke_kem_extract_and_expand(dh.as_bytes(), &kem_context);
    hpke_open(&shared_secret, HPKE_ENVELOPE_INFO, &envelope[X25519_KEY_BYTES..], aad)
        .map_err(|_| CryptoError::WrongRecipient)
}

pub fn encode_envelope(envelope: &[u8]) -> String {
    encode_base64(envelope)
}

pub fn decode_envelope(value: &str) -> CryptoResult<Vec<u8>> {
    decode_base64(value).map_err(|err| CryptoError::MalformedCryptoMetadata(err.to_string()))
}

pub fn encode_base64(value: &[u8]) -> String {
    BASE64_STANDARD.encode(value)
}

pub fn decode_base64(value: &str) -> CryptoResult<Vec<u8>> {
    BASE64_STANDARD
        .decode(value)
        .map_err(|err| CryptoError::MalformedCryptoMetadata(err.to_string()))
}

fn hpke_seal(shared_secret: &[u8], info: &[u8], plaintext: &[u8], aad: &[u8]) -> CryptoResult<Vec<u8>> {
    let (key, nonce) = hpke_key_schedule(shared_secret, info);
    seal_content_aes_256_gcm(&key, &nonce, plaintext, aad)
}

fn hpke_open(shared_secret: &[u8], info: &[u8], ciphertext: &[u8], aad: &[u8]) -> CryptoResult<Vec<u8>> {
    let (key, nonce) = hpke_key_schedule(shared_secret, info);
    open_content_aes_256_gcm(&key, &nonce, ciphertext, aad)
}

fn hpke_key_schedule(shared_secret: &[u8], info: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let suite_id = hpke_suite_id();
    let psk_id_hash = hpke_labeled_extract(&suite_id, None, b"psk_id_hash", &[]);
    let info_hash = hpke_labeled_extract(&suite_id, None, b"info_hash", info);
    let mut context = vec![0_u8];
    context.extend_from_slice(&psk_id_hash);
    context.extend_from_slice(&info_hash);
    let secret = hpke_labeled_extract(&suite_id, Some(shared_secret), b"secret", &[]);
    let key = hpke_labeled_expand(&secret, &suite_id, b"key", &context, AES_256_GCM_KEY_BYTES);
    let nonce = hpke_labeled_expand(&secret, &suite_id, b"base_nonce", &context, AES_GCM_NONCE_BYTES);
    (key, nonce)
}

fn hpke_kem_extract_and_expand(dh: &[u8], kem_context: &[u8]) -> Vec<u8> {
    let suite_id = hpke_kem_suite_id();
    let eae_prk = hpke_labeled_extract(&suite_id, None, b"eae_prk", dh);
    hpke_labeled_expand(&eae_prk, &suite_id, b"shared_secret", kem_context, 32)
}

fn hpke_labeled_extract(suite_id: &[u8], salt: Option<&[u8]>, label: &[u8], ikm: &[u8]) -> Vec<u8> {
    let mut labeled_ikm = HPKE_VERSION_LABEL.to_vec();
    labeled_ikm.extend_from_slice(suite_id);
    labeled_ikm.extend_from_slice(label);
    labeled_ikm.extend_from_slice(ikm);
    hkdf_extract(salt, &labeled_ikm)
}

fn hpke_labeled_expand(prk: &[u8], suite_id: &[u8], label: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let mut labeled_info = (length as u16).to_be_bytes().to_vec();
    labeled_info.extend_from_slice(HPKE_VERSION_LABEL);
    labeled_info.extend_from_slice(suite_id);
    labeled_info.extend_from_slice(label);
    labeled_info.extend_from_slice(info);
    hkdf_expand(prk, &labeled_info, length)
}

fn hkdf_extract(salt: Option<&[u8]>, ikm: &[u8]) -> Vec<u8> {
    let zero_salt = [0_u8; 32];
    let mut mac = <HmacSha256 as Mac>::new_from_slice(salt.unwrap_or(&zero_salt)).expect("HMAC accepts any key length");
    mac.update(ikm);
    mac.finalize().into_bytes().to_vec()
}

fn hkdf_expand(prk: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let mut result = Vec::with_capacity(length);
    let mut previous = Vec::new();
    let mut counter = 1_u8;
    while result.len() < length {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(prk).expect("HMAC accepts any key length");
        mac.update(&previous);
        mac.update(info);
        mac.update(&[counter]);
        previous = mac.finalize().into_bytes().to_vec();
        result.extend_from_slice(&previous);
        counter = counter.wrapping_add(1);
    }
    result.truncate(length);
    result
}

fn hpke_kem_suite_id() -> Vec<u8> {
    let mut suite = b"KEM".to_vec();
    suite.extend_from_slice(HPKE_KEM_ID);
    suite
}

fn hpke_suite_id() -> Vec<u8> {
    let mut suite = b"HPKE".to_vec();
    suite.extend_from_slice(HPKE_KEM_ID);
    suite.extend_from_slice(HPKE_KDF_ID);
    suite.extend_from_slice(HPKE_AEAD_ID);
    suite
}

fn fixed_32(value: &[u8], message: &str) -> CryptoResult<[u8; X25519_KEY_BYTES]> {
    value
        .try_into()
        .map_err(|_| CryptoError::MalformedCryptoMetadata(message.to_string()))
}

fn string_field(value: Option<&Value>) -> Option<String> {
    match value {
        Some(Value::String(value)) => Some(value.clone()),
        Some(value) if !value.is_null() => Some(value.to_string()),
        _ => None,
    }
}
