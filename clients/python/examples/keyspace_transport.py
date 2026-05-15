# Copyright (c) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-only
#
# This file is part of Custodia.
# Custodia is distributed under the GNU Affero General Public License v3.0.
# See the accompanying LICENSE file for details.

"""Minimal Custodia Python transport example using namespace/key helpers.

This example sends only opaque ciphertext and envelope strings. It does not
perform local encryption; use the high-level crypto example when the Python SDK
should create ciphertext and recipient envelopes locally.
"""

from __future__ import annotations

from custodia_client import CustodiaClient, CreateSecretPayload, PermissionRead, RecipientEnvelope


def build_client() -> CustodiaClient:
    return CustodiaClient(
        server_url="https://vault.example:8443",
        cert_file="client_alice.crt",
        key_file="client_alice.key",
        ca_file="ca.crt",
    )


def create_opaque_secret() -> dict[str, object]:
    client = build_client()
    return client.create_secret_payload(
        CreateSecretPayload(
            namespace="db01",
            key="user:sys",
            ciphertext="base64-opaque-ciphertext",
            envelopes=[RecipientEnvelope(client_id="client_alice", envelope="base64-opaque-envelope")],
            permissions=PermissionRead,
            crypto_metadata={"version": "custodia.client-crypto.v1"},
        )
    )
