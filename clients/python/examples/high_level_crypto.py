# Copyright (c) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-only
#
# This file is part of Custodia.
# Custodia is distributed under the GNU Affero General Public License v3.0.
# See the accompanying LICENSE file for details.

"""Minimal Custodia Python high-level crypto example.

The SDK encrypts plaintext locally and sends only ciphertext, crypto metadata and
recipient envelopes to the server. Private keys stay in application-controlled
local storage.
"""

from __future__ import annotations

from custodia_client import (
    CryptoOptions,
    CustodiaClient,
    StaticPrivateKeyProvider,
    StaticPublicKeyResolver,
    X25519PrivateKeyHandle,
    derive_x25519_recipient_public_key,
)

ALICE_PRIVATE_KEY = b"1" * 32
BOB_PRIVATE_KEY_FOR_EXAMPLE_ONLY = b"2" * 32


def build_client() -> CustodiaClient:
    return CustodiaClient(
        server_url="https://vault.example:8443",
        cert_file="client_alice.crt",
        key_file="client_alice.key",
        ca_file="ca.crt",
    )


def create_encrypted_secret() -> dict[str, object]:
    client = build_client()
    crypto = client.with_crypto(
        CryptoOptions(
            public_key_resolver=StaticPublicKeyResolver(
                {
                    "client_alice": derive_x25519_recipient_public_key("client_alice", ALICE_PRIVATE_KEY),
                    "client_bob": derive_x25519_recipient_public_key("client_bob", BOB_PRIVATE_KEY_FOR_EXAMPLE_ONLY),
                }
            ),
            private_key_provider=StaticPrivateKeyProvider(
                X25519PrivateKeyHandle("client_alice", ALICE_PRIVATE_KEY),
            ),
        )
    )
    return crypto.create_encrypted_secret_by_key(
        namespace="db01",
        key="user:sys",
        plaintext=b"correct horse battery staple",
        recipients=["client_bob"],
    )
