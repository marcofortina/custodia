# Copyright (c) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-only
#
# This file is part of Custodia.
# Custodia is distributed under the GNU Affero General Public License v3.0.
# See the accompanying LICENSE file for details.

"""Custodia high-level client crypto helpers.

The server stores only opaque ciphertext, crypto metadata and recipient
envelopes. This module owns the local AES-GCM and HPKE-v1 work needed by the
Python SDK, and it mirrors the shared test vectors used by the other language
clients.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Sequence

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


CRYPTO_VERSION_V1 = "custodia.client-crypto.v1"
CONTENT_CIPHER_V1 = "aes-256-gcm"
ENVELOPE_SCHEME_HPKE_V1 = "hpke-v1"
AES_256_GCM_KEY_BYTES = 32
AES_GCM_NONCE_BYTES = 12
AES_GCM_TAG_BYTES = 16
X25519_KEY_BYTES = 32
_HPKE_ENVELOPE_INFO = b"custodia.client-crypto.v1 envelope"
_HPKE_KEM_ID = b"\x00\x20"  # DHKEM(X25519, HKDF-SHA256)
_HPKE_KDF_ID = b"\x00\x01"  # HKDF-SHA256
_HPKE_AEAD_ID = b"\x00\x02"  # AES-256-GCM
_HPKE_KEM_SUITE_ID = b"KEM" + _HPKE_KEM_ID
_HPKE_SUITE_ID = b"HPKE" + _HPKE_KEM_ID + _HPKE_KDF_ID + _HPKE_AEAD_ID
_HPKE_VERSION_LABEL = b"HPKE-v1"


class CryptoError(ValueError):
    pass


class UnsupportedCryptoVersion(CryptoError):
    pass


class UnsupportedContentCipher(CryptoError):
    pass


class UnsupportedEnvelopeScheme(CryptoError):
    pass


class MalformedCryptoMetadata(CryptoError):
    pass


class MalformedAAD(CryptoError):
    pass


class CiphertextAuthenticationFailed(CryptoError):
    pass


class WrongRecipient(CryptoError):
    pass


@dataclass(frozen=True)
class CanonicalAADInputs:
    namespace: str = ""
    key: str = ""

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any] | None) -> "CanonicalAADInputs":
        if value is None:
            return cls()
        return cls(
            namespace=str(value.get("namespace") or ""),
            key=str(value.get("key") or ""),
        )

    def to_metadata_dict(self) -> dict[str, str]:
        payload: dict[str, str] = {}
        if self.namespace:
            payload["namespace"] = self.namespace
        if self.key:
            payload["key"] = self.key
        return payload


@dataclass(frozen=True)
class CryptoMetadata:
    version: str = CRYPTO_VERSION_V1
    content_cipher: str = CONTENT_CIPHER_V1
    envelope_scheme: str = ENVELOPE_SCHEME_HPKE_V1
    content_nonce_b64: str = ""
    aad: CanonicalAADInputs | None = None

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any]) -> "CryptoMetadata":
        return cls(
            version=str(payload.get("version") or ""),
            content_cipher=str(payload.get("content_cipher") or ""),
            envelope_scheme=str(payload.get("envelope_scheme") or ""),
            content_nonce_b64=str(payload.get("content_nonce_b64") or ""),
            aad=CanonicalAADInputs.from_mapping(payload.get("aad")) if payload.get("aad") is not None else None,
        )

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "version": self.version,
            "content_cipher": self.content_cipher,
            "envelope_scheme": self.envelope_scheme,
        }
        if self.content_nonce_b64:
            payload["content_nonce_b64"] = self.content_nonce_b64
        if self.aad is not None:
            payload["aad"] = self.aad.to_metadata_dict()
        return payload

    def canonical_aad_inputs(self, fallback: CanonicalAADInputs) -> CanonicalAADInputs:
        return self.aad if self.aad is not None else fallback


def metadata_v1(aad: CanonicalAADInputs, content_nonce: bytes) -> CryptoMetadata:
    return CryptoMetadata(content_nonce_b64=_b64encode(content_nonce), aad=aad)


def parse_metadata(payload: Mapping[str, Any] | bytes | str) -> CryptoMetadata:
    if isinstance(payload, bytes):
        try:
            value = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise MalformedCryptoMetadata("malformed crypto metadata") from exc
    elif isinstance(payload, str):
        try:
            value = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise MalformedCryptoMetadata("malformed crypto metadata") from exc
    else:
        value = dict(payload)
    metadata = CryptoMetadata.from_mapping(value)
    validate_metadata(metadata)
    return metadata


def validate_metadata(metadata: CryptoMetadata) -> None:
    if metadata.version != CRYPTO_VERSION_V1:
        raise UnsupportedCryptoVersion("unsupported crypto metadata version")
    if metadata.content_cipher != CONTENT_CIPHER_V1:
        raise UnsupportedContentCipher("unsupported content cipher")
    if metadata.envelope_scheme != ENVELOPE_SCHEME_HPKE_V1:
        raise UnsupportedEnvelopeScheme("unsupported envelope scheme")


def build_canonical_aad(metadata: CryptoMetadata | Mapping[str, Any], inputs: CanonicalAADInputs) -> bytes:
    """Return the deterministic JSON AAD bound into content and envelope AEADs."""
    if isinstance(metadata, Mapping):
        metadata = CryptoMetadata.from_mapping(metadata)
    validate_metadata(metadata)
    if not inputs.namespace or not inputs.key:
        raise MalformedAAD("namespace and key are required")
    document: dict[str, str] = {
        "version": metadata.version,
        "content_cipher": metadata.content_cipher,
        "envelope_scheme": metadata.envelope_scheme,
    }
    document["namespace"] = inputs.namespace
    document["key"] = inputs.key
    return json.dumps(document, separators=(",", ":")).encode("utf-8")


def canonical_aad_sha256(aad: bytes) -> str:
    return hashlib.sha256(aad).hexdigest()


def seal_content_aes_256_gcm(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    if len(key) != AES_256_GCM_KEY_BYTES:
        raise MalformedCryptoMetadata("invalid content key")
    if len(nonce) != AES_GCM_NONCE_BYTES:
        raise MalformedCryptoMetadata("invalid content nonce")
    return AESGCM(key).encrypt(nonce, plaintext, aad)


def open_content_aes_256_gcm(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    if len(key) != AES_256_GCM_KEY_BYTES:
        raise MalformedCryptoMetadata("invalid content key")
    if len(nonce) != AES_GCM_NONCE_BYTES:
        raise MalformedCryptoMetadata("invalid content nonce")
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except Exception as exc:  # cryptography intentionally exposes InvalidTag without details.
        raise CiphertextAuthenticationFailed("ciphertext authentication failed") from exc


def derive_x25519_public_key(private_key: bytes) -> bytes:
    if len(private_key) != X25519_KEY_BYTES:
        raise MalformedCryptoMetadata("invalid x25519 private key")
    key = x25519.X25519PrivateKey.from_private_bytes(private_key)
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def seal_hpke_v1_envelope(recipient_public_key: bytes, sender_ephemeral_private_key: bytes, dek: bytes, aad: bytes) -> bytes:
    """Seal a DEK for one recipient using the fixed Custodia HPKE-v1 suite."""
    if len(recipient_public_key) != X25519_KEY_BYTES or len(sender_ephemeral_private_key) != X25519_KEY_BYTES:
        raise MalformedCryptoMetadata("invalid envelope key")
    sk_e = x25519.X25519PrivateKey.from_private_bytes(sender_ephemeral_private_key)
    pk_r = x25519.X25519PublicKey.from_public_bytes(recipient_public_key)
    enc = sk_e.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    dh = sk_e.exchange(pk_r)
    shared_secret = _hpke_kem_extract_and_expand(dh, enc + recipient_public_key)
    sealed = _hpke_seal(shared_secret, _HPKE_ENVELOPE_INFO, dek, aad)
    return enc + sealed


def open_hpke_v1_envelope(recipient_private_key: bytes, envelope: bytes, aad: bytes) -> bytes:
    if len(recipient_private_key) != X25519_KEY_BYTES:
        raise MalformedCryptoMetadata("invalid envelope key")
    if len(envelope) <= X25519_KEY_BYTES + AES_GCM_TAG_BYTES:
        raise MalformedCryptoMetadata("malformed envelope")
    sk_r = x25519.X25519PrivateKey.from_private_bytes(recipient_private_key)
    pk_e = x25519.X25519PublicKey.from_public_bytes(envelope[:X25519_KEY_BYTES])
    recipient_public_key = sk_r.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    dh = sk_r.exchange(pk_e)
    shared_secret = _hpke_kem_extract_and_expand(dh, envelope[:X25519_KEY_BYTES] + recipient_public_key)
    try:
        return _hpke_open(shared_secret, _HPKE_ENVELOPE_INFO, envelope[X25519_KEY_BYTES:], aad)
    except CiphertextAuthenticationFailed as exc:
        raise WrongRecipient("wrong recipient") from exc


def encode_envelope(envelope: bytes) -> str:
    return _b64encode(envelope)


def decode_envelope(value: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise MalformedCryptoMetadata("malformed envelope") from exc

@dataclass(frozen=True)
class RecipientPublicKey:
    client_id: str
    scheme: str
    public_key: bytes
    fingerprint: str = ""


class PublicKeyResolver:
    def resolve_recipient_public_key(self, client_id: str) -> RecipientPublicKey:
        raise NotImplementedError


class PrivateKeyHandle:
    @property
    def client_id(self) -> str:
        raise NotImplementedError

    @property
    def scheme(self) -> str:
        raise NotImplementedError

    def open_envelope(self, envelope: bytes, aad: bytes) -> bytes:
        raise NotImplementedError


class PrivateKeyProvider:
    def current_private_key(self) -> PrivateKeyHandle:
        raise NotImplementedError


@dataclass(frozen=True)
class X25519PrivateKeyHandle(PrivateKeyHandle):
    _client_id: str
    private_key: bytes

    def __post_init__(self) -> None:
        derive_x25519_public_key(self.private_key)

    @property
    def client_id(self) -> str:
        return self._client_id

    @property
    def scheme(self) -> str:
        return ENVELOPE_SCHEME_HPKE_V1

    def open_envelope(self, envelope: bytes, aad: bytes) -> bytes:
        return open_hpke_v1_envelope(self.private_key, envelope, aad)


def derive_x25519_recipient_public_key(client_id: str, private_key: bytes) -> RecipientPublicKey:
    return RecipientPublicKey(client_id=client_id, scheme=ENVELOPE_SCHEME_HPKE_V1, public_key=derive_x25519_public_key(private_key))


@dataclass(frozen=True)
class StaticPrivateKeyProvider(PrivateKeyProvider):
    private_key: PrivateKeyHandle

    def current_private_key(self) -> PrivateKeyHandle:
        return self.private_key


@dataclass(frozen=True)
class StaticPublicKeyResolver(PublicKeyResolver):
    public_keys: Mapping[str, RecipientPublicKey]

    def resolve_recipient_public_key(self, client_id: str) -> RecipientPublicKey:
        if client_id not in self.public_keys:
            raise KeyError(f"missing recipient public key: {client_id}")
        return self.public_keys[client_id]


@dataclass(frozen=True)
class CryptoOptions:
    public_key_resolver: PublicKeyResolver
    private_key_provider: PrivateKeyProvider
    random_source: Callable[[int], bytes] = os.urandom

    def validate(self) -> None:
        if self.public_key_resolver is None:
            raise ValueError("public key resolver is required")
        if self.private_key_provider is None:
            raise ValueError("private key provider is required")
        if self.random_source is None:
            raise ValueError("random source is required")


@dataclass(frozen=True)
class DecryptedSecret:
    secret_id: str
    version_id: str
    plaintext: bytes
    crypto_metadata: Mapping[str, Any]
    permissions: int
    granted_at: str = ""
    access_expires_at: str | None = None


@dataclass(frozen=True)
class CryptoCustodiaClient:
    transport: Any
    options: CryptoOptions

    def __post_init__(self) -> None:
        self.options.validate()

    def create_encrypted_secret(
        self,
        name: str,
        plaintext: bytes,
        recipients: Sequence[str] = (),
        permissions: int = 7,
        expires_at: str | None = None,
    ) -> dict[str, Any]:
        if not name.strip():
            raise ValueError("secret name is required")
        dek = self._random(AES_256_GCM_KEY_BYTES)
        nonce = self._random(AES_GCM_NONCE_BYTES)
        aad_inputs = CanonicalAADInputs(namespace="default", key=name)
        metadata = metadata_v1(aad_inputs, nonce)
        aad = build_canonical_aad(metadata, aad_inputs)
        ciphertext = seal_content_aes_256_gcm(dek, nonce, plaintext, aad)
        payload: dict[str, Any] = {
            "name": name,
            "ciphertext": _b64encode(ciphertext),
            "crypto_metadata": metadata.to_dict(),
            "envelopes": self._seal_recipient_envelopes(self._normalized_recipients(recipients), dek, aad),
            "permissions": permissions,
        }
        if expires_at:
            payload["expires_at"] = expires_at
        return self.transport.create_secret(payload)

    def create_encrypted_secret_by_key(
        self,
        namespace: str,
        key: str,
        plaintext: bytes,
        recipients: Sequence[str] = (),
        permissions: int = 7,
        expires_at: str | None = None,
    ) -> dict[str, Any]:
        namespace = _normalize_namespace(namespace)
        key = _require_key(key)
        dek = self._random(AES_256_GCM_KEY_BYTES)
        nonce = self._random(AES_GCM_NONCE_BYTES)
        aad_inputs = CanonicalAADInputs(namespace=namespace, key=key)
        metadata = metadata_v1(aad_inputs, nonce)
        aad = build_canonical_aad(metadata, aad_inputs)
        ciphertext = seal_content_aes_256_gcm(dek, nonce, plaintext, aad)
        payload: dict[str, Any] = {
            "namespace": namespace,
            "key": key,
            "name": key,
            "ciphertext": _b64encode(ciphertext),
            "crypto_metadata": metadata.to_dict(),
            "envelopes": self._seal_recipient_envelopes(self._normalized_recipients(recipients), dek, aad),
            "permissions": permissions,
        }
        if expires_at:
            payload["expires_at"] = expires_at
        return self.transport.create_secret(payload)

    def create_encrypted_secret_version(
        self,
        secret_id: str,
        plaintext: bytes,
        recipients: Sequence[str] = (),
        permissions: int = 7,
        expires_at: str | None = None,
    ) -> dict[str, Any]:
        if not secret_id.strip():
            raise ValueError("secret id is required")
        dek = self._random(AES_256_GCM_KEY_BYTES)
        nonce = self._random(AES_GCM_NONCE_BYTES)
        secret = self.transport.get_secret(secret_id)
        namespace = _normalize_namespace(str(secret.get("namespace") or ""))
        key = _require_key(str(secret.get("key") or ""))
        aad_inputs = CanonicalAADInputs(namespace=namespace, key=key)
        metadata = metadata_v1(aad_inputs, nonce)
        aad = build_canonical_aad(metadata, aad_inputs)
        ciphertext = seal_content_aes_256_gcm(dek, nonce, plaintext, aad)
        payload: dict[str, Any] = {
            "ciphertext": _b64encode(ciphertext),
            "crypto_metadata": metadata.to_dict(),
            "envelopes": self._seal_recipient_envelopes(self._normalized_recipients(recipients), dek, aad),
            "permissions": permissions,
        }
        if expires_at:
            payload["expires_at"] = expires_at
        return self.transport.create_secret_version(secret_id, payload)

    def create_encrypted_secret_version_by_key(
        self,
        namespace: str,
        key: str,
        plaintext: bytes,
        recipients: Sequence[str] = (),
        permissions: int = 7,
        expires_at: str | None = None,
    ) -> dict[str, Any]:
        namespace = _normalize_namespace(namespace)
        key = _require_key(key)
        dek = self._random(AES_256_GCM_KEY_BYTES)
        nonce = self._random(AES_GCM_NONCE_BYTES)
        aad_inputs = CanonicalAADInputs(namespace=namespace, key=key)
        metadata = metadata_v1(aad_inputs, nonce)
        aad = build_canonical_aad(metadata, aad_inputs)
        ciphertext = seal_content_aes_256_gcm(dek, nonce, plaintext, aad)
        payload: dict[str, Any] = {
            "ciphertext": _b64encode(ciphertext),
            "crypto_metadata": metadata.to_dict(),
            "envelopes": self._seal_recipient_envelopes(self._normalized_recipients(recipients), dek, aad),
            "permissions": permissions,
        }
        if expires_at:
            payload["expires_at"] = expires_at
        return self.transport.create_secret_version_by_key(namespace, key, payload)

    def read_decrypted_secret(self, secret_id: str) -> DecryptedSecret:
        secret = self.transport.get_secret(secret_id)
        metadata = parse_metadata(secret.get("crypto_metadata") or {})
        fallback = CanonicalAADInputs(
            namespace=_normalize_namespace(str(secret.get("namespace") or "")),
            key=_require_key(str(secret.get("key") or "")),
        )
        aad_inputs = metadata.canonical_aad_inputs(fallback)
        aad = build_canonical_aad(metadata, aad_inputs)
        if not metadata.content_nonce_b64:
            raise MalformedCryptoMetadata("missing content nonce")
        nonce = base64.b64decode(metadata.content_nonce_b64, validate=True)
        dek = self._open_secret_envelope(str(secret.get("envelope") or ""), aad)
        ciphertext = base64.b64decode(str(secret.get("ciphertext") or ""), validate=True)
        plaintext = open_content_aes_256_gcm(dek, nonce, ciphertext, aad)
        return DecryptedSecret(
            secret_id=str(secret.get("secret_id") or ""),
            version_id=str(secret.get("version_id") or ""),
            plaintext=plaintext,
            crypto_metadata=dict(metadata.to_dict()),
            permissions=int(secret.get("permissions") or 0),
            granted_at=str(secret.get("granted_at") or ""),
            access_expires_at=secret.get("access_expires_at"),
        )

    def read_decrypted_secret_by_key(self, namespace: str, key: str) -> DecryptedSecret:
        namespace = _normalize_namespace(namespace)
        key = _require_key(key)
        secret = self.transport.get_secret_by_key(namespace, key)
        metadata = parse_metadata(secret.get("crypto_metadata") or {})
        fallback = CanonicalAADInputs(
            namespace=namespace,
            key=key,
        )
        aad_inputs = metadata.canonical_aad_inputs(fallback)
        aad = build_canonical_aad(metadata, aad_inputs)
        if not metadata.content_nonce_b64:
            raise MalformedCryptoMetadata("missing content nonce")
        nonce = base64.b64decode(metadata.content_nonce_b64, validate=True)
        dek = self._open_secret_envelope(str(secret.get("envelope") or ""), aad)
        ciphertext = base64.b64decode(str(secret.get("ciphertext") or ""), validate=True)
        plaintext = open_content_aes_256_gcm(dek, nonce, ciphertext, aad)
        return DecryptedSecret(
            secret_id=str(secret.get("secret_id") or ""),
            version_id=str(secret.get("version_id") or ""),
            plaintext=plaintext,
            crypto_metadata=dict(metadata.to_dict()),
            permissions=int(secret.get("permissions") or 0),
            granted_at=str(secret.get("granted_at") or ""),
            access_expires_at=secret.get("access_expires_at"),
        )

    def share_encrypted_secret(
        self,
        secret_id: str,
        target_client_id: str,
        permissions: int = 4,
        expires_at: str | None = None,
    ) -> dict[str, Any]:
        if not target_client_id.strip():
            raise ValueError("target client id is required")
        secret = self.transport.get_secret(secret_id)
        metadata = parse_metadata(secret.get("crypto_metadata") or {})
        fallback = CanonicalAADInputs(
            namespace=_normalize_namespace(str(secret.get("namespace") or "")),
            key=_require_key(str(secret.get("key") or "")),
        )
        aad_inputs = metadata.canonical_aad_inputs(fallback)
        aad = build_canonical_aad(metadata, aad_inputs)  # type: ignore[name-defined]
        dek = self._open_secret_envelope(str(secret.get("envelope") or ""), aad)
        envelope = self._seal_recipient_envelopes([target_client_id], dek, aad)[0]
        payload: dict[str, Any] = {
            "version_id": str(secret.get("version_id") or ""),
            "target_client_id": target_client_id,
            "envelope": envelope["envelope"],
            "permissions": permissions,
        }
        if expires_at:
            payload["expires_at"] = expires_at
        return self.transport.share_secret(secret_id, payload)

    def share_encrypted_secret_by_key(
        self,
        namespace: str,
        key: str,
        target_client_id: str,
        permissions: int = 4,
        expires_at: str | None = None,
    ) -> dict[str, Any]:
        namespace = _normalize_namespace(namespace)
        key = _require_key(key)
        if not target_client_id.strip():
            raise ValueError("target client id is required")
        secret = self.transport.get_secret_by_key(namespace, key)
        metadata = parse_metadata(secret.get("crypto_metadata") or {})
        fallback = CanonicalAADInputs(
            namespace=namespace,
            key=key,
        )
        aad_inputs = metadata.canonical_aad_inputs(fallback)
        aad = build_canonical_aad(metadata, aad_inputs)
        dek = self._open_secret_envelope(str(secret.get("envelope") or ""), aad)
        envelope = self._seal_recipient_envelopes([target_client_id], dek, aad)[0]
        payload: dict[str, Any] = {
            "version_id": str(secret.get("version_id") or ""),
            "target_client_id": target_client_id,
            "envelope": envelope["envelope"],
            "permissions": permissions,
        }
        if expires_at:
            payload["expires_at"] = expires_at
        return self.transport.share_secret_by_key(namespace, key, payload)

    def _normalized_recipients(self, recipients: Sequence[str]) -> list[str]:
        current = self.options.private_key_provider.current_private_key()
        normalized: list[str] = []
        seen: set[str] = set()
        if current.client_id:
            normalized.append(current.client_id)
            seen.add(current.client_id)
        for recipient in recipients:
            recipient = recipient.strip()
            if recipient and recipient not in seen:
                normalized.append(recipient)
                seen.add(recipient)
        if not normalized:
            raise ValueError("missing recipient envelope")
        return normalized

    def _seal_recipient_envelopes(self, recipients: Sequence[str], dek: bytes, aad: bytes) -> list[dict[str, str]]:
        envelopes: list[dict[str, str]] = []
        for recipient_id in recipients:
            public_key = self.options.public_key_resolver.resolve_recipient_public_key(recipient_id)
            if public_key.scheme != ENVELOPE_SCHEME_HPKE_V1:
                raise UnsupportedEnvelopeScheme("unsupported envelope scheme")
            envelope = seal_hpke_v1_envelope(public_key.public_key, self._random(X25519_KEY_BYTES), dek, aad)
            envelopes.append({"client_id": recipient_id, "envelope": encode_envelope(envelope)})
        return envelopes

    def _open_secret_envelope(self, encoded_envelope: str, aad: bytes) -> bytes:
        private_key = self.options.private_key_provider.current_private_key()
        if private_key.scheme != ENVELOPE_SCHEME_HPKE_V1:
            raise UnsupportedEnvelopeScheme("unsupported envelope scheme")
        return private_key.open_envelope(decode_envelope(encoded_envelope), aad)

    def _random(self, length: int) -> bytes:
        value = self.options.random_source(length)
        if len(value) != length:
            raise ValueError("random source returned invalid length")
        return value


def _normalize_namespace(namespace: str) -> str:
    namespace = str(namespace or "").strip()
    return namespace or "default"


def _require_key(key: str) -> str:
    key = str(key or "").strip()
    if not key:
        raise ValueError("secret key is required")
    return key


def _hpke_seal(shared_secret: bytes, info: bytes, plaintext: bytes, aad: bytes) -> bytes:
    key, nonce = _hpke_key_schedule(shared_secret, info)
    return AESGCM(key).encrypt(nonce, plaintext, aad)


def _hpke_open(shared_secret: bytes, info: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    key, nonce = _hpke_key_schedule(shared_secret, info)
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except Exception as exc:
        raise CiphertextAuthenticationFailed("envelope authentication failed") from exc


def _hpke_key_schedule(shared_secret: bytes, info: bytes) -> tuple[bytes, bytes]:
    psk_id_hash = _hpke_labeled_extract(_HPKE_SUITE_ID, None, b"psk_id_hash", b"")
    info_hash = _hpke_labeled_extract(_HPKE_SUITE_ID, None, b"info_hash", info)
    context = b"\x00" + psk_id_hash + info_hash
    secret = _hpke_labeled_extract(_HPKE_SUITE_ID, shared_secret, b"secret", b"")
    key = _hpke_labeled_expand(secret, _HPKE_SUITE_ID, b"key", context, AES_256_GCM_KEY_BYTES)
    nonce = _hpke_labeled_expand(secret, _HPKE_SUITE_ID, b"base_nonce", context, AES_GCM_NONCE_BYTES)
    return key, nonce


def _hpke_kem_extract_and_expand(dh: bytes, kem_context: bytes) -> bytes:
    eae_prk = _hpke_labeled_extract(_HPKE_KEM_SUITE_ID, None, b"eae_prk", dh)
    return _hpke_labeled_expand(eae_prk, _HPKE_KEM_SUITE_ID, b"shared_secret", kem_context, hashlib.sha256().digest_size)


def _hpke_labeled_extract(suite_id: bytes, salt: bytes | None, label: bytes, ikm: bytes) -> bytes:
    return _hkdf_extract(salt, _HPKE_VERSION_LABEL + suite_id + label + ikm)


def _hpke_labeled_expand(prk: bytes, suite_id: bytes, label: bytes, info: bytes, length: int) -> bytes:
    labeled_info = length.to_bytes(2, "big") + _HPKE_VERSION_LABEL + suite_id + label + info
    return _hkdf_expand(prk, labeled_info, length)


def _hkdf_extract(salt: bytes | None, ikm: bytes) -> bytes:
    if salt is None:
        salt = b"\x00" * hashlib.sha256().digest_size
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    result = b""
    previous = b""
    counter = 1
    while len(result) < length:
        previous = hmac.new(prk, previous + info + bytes([counter]), hashlib.sha256).digest()
        result += previous
        counter += 1
    return result[:length]


def _b64encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")
