# Copyright (c) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-only
#
# This file is part of Custodia.
# Custodia is distributed under the GNU Affero General Public License v3.0.
# See the accompanying LICENSE file for details.

from __future__ import annotations

import base64
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from custodia_client import (  # noqa: E402
    CanonicalAADInputs,
    CryptoCustodiaClient,
    CryptoOptions,
    StaticPrivateKeyProvider,
    StaticPublicKeyResolver,
    X25519PrivateKeyHandle,
    derive_x25519_recipient_public_key,
)
from custodia_client.crypto import metadata_v1  # noqa: E402


VECTOR_DIR = Path(__file__).resolve().parents[3] / "testdata" / "client-crypto" / "v1"


def _vector(name: str) -> dict[str, object]:
    return json.loads((VECTOR_DIR / name).read_text())


def _b64(value: str) -> bytes:
    return base64.b64decode(value)


class _RandomSource:
    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = list(chunks)

    def __call__(self, length: int) -> bytes:
        if not self._chunks:
            raise AssertionError("unexpected random read")
        value = self._chunks.pop(0)
        if len(value) != length:
            raise AssertionError(f"expected {length} random bytes, got {len(value)}")
        return value


class _Transport:
    def __init__(self) -> None:
        self.created_payload: dict[str, object] | None = None
        self.version_payload: dict[str, object] | None = None
        self.shared_payload: dict[str, object] | None = None
        self.secret_response: dict[str, object] = {}

    def create_secret(self, payload: dict[str, object]) -> dict[str, str]:
        self.created_payload = payload
        return {"secret_id": "created-secret", "version_id": "created-version"}

    def create_secret_version(self, secret_id: str, payload: dict[str, object]) -> dict[str, str]:
        self.version_payload = {"secret_id": secret_id, **payload}
        return {"secret_id": secret_id, "version_id": "created-version"}

    def create_secret_version_by_key(self, namespace: str, key: str, payload: dict[str, object]) -> dict[str, str]:
        self.version_payload = {"namespace": namespace, "key": key, **payload}
        return {"secret_id": "created-secret", "version_id": "created-version"}

    def get_secret(self, secret_id: str) -> dict[str, object]:
        if secret_id != self.secret_response.get("secret_id"):
            raise AssertionError("unexpected secret id")
        return self.secret_response

    def get_secret_by_key(self, namespace: str, key: str) -> dict[str, object]:
        if namespace != self.secret_response.get("namespace") or key != self.secret_response.get("key"):
            raise AssertionError("unexpected secret keyspace")
        return self.secret_response

    def share_secret(self, secret_id: str, payload: dict[str, object]) -> dict[str, bool]:
        self.shared_payload = {"secret_id": secret_id, **payload}
        return {"ok": True}

    def share_secret_by_key(self, namespace: str, key: str, payload: dict[str, object]) -> dict[str, bool]:
        self.shared_payload = {"namespace": namespace, "key": key, **payload}
        return {"ok": True}


def _crypto_options(random_source: _RandomSource) -> CryptoOptions:
    alice_key = b"1" * 32
    bob_key = b"2" * 32
    alice_public = derive_x25519_recipient_public_key("client_alice", alice_key)
    bob_public = derive_x25519_recipient_public_key("client_bob", bob_key)
    return CryptoOptions(
        public_key_resolver=StaticPublicKeyResolver({"client_alice": alice_public, "client_bob": bob_public}),
        private_key_provider=StaticPrivateKeyProvider(X25519PrivateKeyHandle("client_alice", alice_key)),
        random_source=random_source,
    )


class PythonHighLevelCryptoClientTest(unittest.TestCase):
    def test_create_encrypted_secret_matches_vector_and_sends_no_plaintext(self) -> None:
        vector = _vector("create_secret_single_recipient.json")
        random_source = _RandomSource([
            _b64(vector["content_dek_b64"]),
            _b64(vector["content_nonce_b64"]),
            _b64(vector["envelopes"][0]["sender_ephemeral_private_key_b64"]),
        ])
        transport = _Transport()
        crypto = CryptoCustodiaClient(transport, _crypto_options(random_source))

        self.assertEqual(
            crypto.create_encrypted_secret("database-password", _b64(vector["plaintext_b64"])),
            {"secret_id": "created-secret", "version_id": "created-version"},
        )
        assert transport.created_payload is not None
        self.assertNotIn("plaintext", transport.created_payload)
        self.assertEqual(transport.created_payload["ciphertext"], vector["ciphertext"])
        self.assertEqual(transport.created_payload["envelopes"], [{"client_id": "client_alice", "envelope": vector["envelopes"][0]["envelope"]}])
        metadata = transport.created_payload["crypto_metadata"]
        self.assertEqual(metadata["content_nonce_b64"], vector["content_nonce_b64"])
        self.assertEqual(metadata["aad"], {"namespace": "default", "key": "database-password", "secret_version": 1})


    def test_create_encrypted_secret_by_key_sends_keyspace_payload(self) -> None:
        random_source = _RandomSource([b"A" * 32, b"B" * 12, b"C" * 32])
        transport = _Transport()
        crypto = CryptoCustodiaClient(transport, _crypto_options(random_source))

        self.assertEqual(
            crypto.create_encrypted_secret_by_key("db01", "user:sys", b"secret"),
            {"secret_id": "created-secret", "version_id": "created-version"},
        )
        assert transport.created_payload is not None
        self.assertEqual(transport.created_payload["namespace"], "db01")
        self.assertEqual(transport.created_payload["key"], "user:sys")
        self.assertEqual(transport.created_payload["crypto_metadata"]["aad"], {"namespace": "db01", "key": "user:sys", "secret_version": 1})

    def test_keyspace_read_share_and_version_helpers(self) -> None:
        random_source = _RandomSource([b"A" * 32, b"B" * 12, b"C" * 32, b"D" * 32, b"E" * 32, b"F" * 12, b"G" * 32])
        transport = _Transport()
        crypto = CryptoCustodiaClient(transport, _crypto_options(random_source))
        crypto.create_encrypted_secret_by_key("db01", "user:sys", b"secret")
        assert transport.created_payload is not None
        transport.secret_response = {
            "secret_id": "created-secret",
            "namespace": "db01",
            "key": "user:sys",
            "version_id": "created-version",
            "ciphertext": transport.created_payload["ciphertext"],
            "crypto_metadata": transport.created_payload["crypto_metadata"],
            "envelope": transport.created_payload["envelopes"][0]["envelope"],
            "permissions": 7,
        }

        self.assertEqual(crypto.read_decrypted_secret_by_key("db01", "user:sys").plaintext, b"secret")
        self.assertEqual(crypto.share_encrypted_secret_by_key("db01", "user:sys", "client_bob"), {"ok": True})
        self.assertEqual(transport.shared_payload["namespace"], "db01")
        self.assertEqual(transport.shared_payload["key"], "user:sys")
        self.assertEqual(transport.shared_payload["target_client_id"], "client_bob")

        crypto.create_encrypted_secret_version_by_key("db01", "user:sys", b"rotated")
        assert transport.version_payload is not None
        self.assertEqual(transport.version_payload["namespace"], "db01")
        self.assertEqual(transport.version_payload["key"], "user:sys")
        self.assertEqual(transport.version_payload["crypto_metadata"]["aad"], {"namespace": "db01", "key": "user:sys", "secret_version": 2})

    def test_read_decrypted_secret_matches_vector(self) -> None:
        vector = _vector("read_secret_authorized_recipient.json")
        transport = _Transport()
        transport.secret_response = {
            "secret_id": "secret-id",
            "namespace": vector["aad_inputs"]["namespace"],
            "key": vector["aad_inputs"]["key"],
            "version_id": "version-id",
            "ciphertext": vector["ciphertext"],
            "crypto_metadata": metadata_v1(
                CanonicalAADInputs(
                    namespace=vector["aad_inputs"]["namespace"],
                    key=vector["aad_inputs"]["key"],
                    secret_version=vector["aad_inputs"]["secret_version"],
                ),
                _b64(vector["content_nonce_b64"]),
            ).to_dict(),
            "envelope": vector["envelope"]["envelope"],
            "permissions": 7,
            "granted_at": "2026-05-04T00:00:00Z",
        }
        crypto = CryptoCustodiaClient(transport, _crypto_options(_RandomSource([])))

        decrypted = crypto.read_decrypted_secret("secret-id")
        self.assertEqual(decrypted.plaintext, _b64(vector["plaintext_b64"]))
        self.assertEqual(decrypted.secret_id, "secret-id")
        self.assertEqual(decrypted.version_id, "version-id")

    def test_share_encrypted_secret_matches_vector(self) -> None:
        read_vector = _vector("read_secret_authorized_recipient.json")
        share_vector = _vector("share_secret_add_recipient.json")
        random_source = _RandomSource([_b64(share_vector["envelope"]["sender_ephemeral_private_key_b64"])])
        transport = _Transport()
        transport.secret_response = {
            "secret_id": "secret-id",
            "namespace": read_vector["aad_inputs"]["namespace"],
            "key": read_vector["aad_inputs"]["key"],
            "version_id": "version-id",
            "ciphertext": read_vector["ciphertext"],
            "crypto_metadata": metadata_v1(
                CanonicalAADInputs(
                    namespace=read_vector["aad_inputs"]["namespace"],
                    key=read_vector["aad_inputs"]["key"],
                    secret_version=read_vector["aad_inputs"]["secret_version"],
                ),
                _b64(read_vector["content_nonce_b64"]),
            ).to_dict(),
            "envelope": read_vector["envelope"]["envelope"],
            "permissions": 7,
            "granted_at": "2026-05-04T00:00:00Z",
        }
        crypto = CryptoCustodiaClient(transport, _crypto_options(random_source))

        self.assertEqual(crypto.share_encrypted_secret("secret-id", "client_bob"), {"ok": True})
        self.assertEqual(
            transport.shared_payload,
            {
                "secret_id": "secret-id",
                "version_id": "version-id",
                "target_client_id": "client_bob",
                "envelope": share_vector["envelope"]["envelope"],
                "permissions": 4,
            },
        )


if __name__ == "__main__":
    unittest.main()
