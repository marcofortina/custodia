# Copyright (c) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-only
#
# This file is part of Custodia.
# Custodia is distributed under the GNU Affero General Public License v3.0.
# See the accompanying LICENSE file for details.

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from custodia_client import (  # noqa: E402
    AccessGrantPayload,
    ActivateAccessPayload,
    CreateSecretPayload,
    CreateSecretVersionPayload,
    CustodiaClient,
    PermissionRead,
    RecipientEnvelope,
    ShareSecretPayload,
)


class _Response:
    content = b'{"ok":true}'
    text = '{"ok":true}'
    headers = {}

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict[str, bool]:
        return {"ok": True}


class PythonTransportTypesTest(unittest.TestCase):
    def test_create_secret_payload_to_dict(self) -> None:
        payload = CreateSecretPayload(
            key="database-password",
            ciphertext="Y2lwaGVy",
            envelopes=[RecipientEnvelope(client_id="client_alice", envelope="ZW52")],
            permissions=PermissionRead,
            crypto_metadata={"version": "custodia.client-crypto.v1"},
        )
        self.assertEqual(
            payload.to_dict(),
            {
                "key": "database-password",
                "ciphertext": "Y2lwaGVy",
                "envelopes": [{"client_id": "client_alice", "envelope": "ZW52"}],
                "permissions": PermissionRead,
                "crypto_metadata": {"version": "custodia.client-crypto.v1"},
            },
        )

    def test_create_secret_payload_to_dict_with_keyspace(self) -> None:
        payload = CreateSecretPayload(
            key="user:sys",
            namespace="db01",
            ciphertext="Y2lwaGVy",
            envelopes=[RecipientEnvelope(client_id="client_alice", envelope="ZW52")],
        )
        self.assertEqual(payload.to_dict()["namespace"], "db01")
        self.assertEqual(payload.to_dict()["key"], "user:sys")

    def test_typed_helpers_send_public_payloads(self) -> None:
        client = CustodiaClient(
            server_url="https://vault.example",
            cert_file="client.crt",
            key_file="client.key",
            ca_file="ca.crt",
        )
        with patch("custodia_client.requests.request", return_value=_Response()) as request:
            self.assertEqual(
                client.create_secret_payload(
                    CreateSecretPayload(
                        key="secret",
                        ciphertext="Y2lwaGVy",
                        envelopes=[RecipientEnvelope("client_alice", "ZW52")],
                    )
                ),
                {"ok": True},
            )
            self.assertEqual(
                client.request_access_grant_payload("secret-id", AccessGrantPayload(target_client_id="client_bob")),
                {"ok": True},
            )
            self.assertEqual(
                client.activate_access_grant_payload("secret-id", "client_bob", ActivateAccessPayload(envelope="ZW52")),
                {"ok": True},
            )
            self.assertEqual(client.get_secret_by_key("db01", "user:sys"), {"ok": True})
            self.assertEqual(client.list_secret_versions_by_key("db01", "user:sys", limit=10), {"ok": True})
            self.assertEqual(client.list_secret_access_by_key("db01", "user:sys", limit=10), {"ok": True})
            self.assertEqual(
                client.share_secret_payload_by_key(
                    "db01",
                    "user:sys",
                    ShareSecretPayload(version_id="version-id", target_client_id="client_bob", envelope="ZW52"),
                ),
                {"ok": True},
            )
            self.assertEqual(client.revoke_access_by_key("db01", "user:sys", "client_bob"), {"ok": True})
            self.assertEqual(
                client.create_secret_version_payload_by_key(
                    "db01",
                    "user:sys",
                    CreateSecretVersionPayload(
                        ciphertext="Y2lwaGVy",
                        envelopes=[RecipientEnvelope("client_alice", "ZW52")],
                    ),
                ),
                {"ok": True},
            )
            self.assertEqual(client.delete_secret_by_key("db01", "user:sys", cascade=True), {"ok": True})
        self.assertEqual(request.call_args_list[0].kwargs["json"]["envelopes"][0]["client_id"], "client_alice")
        self.assertNotIn("plaintext", request.call_args_list[0].kwargs["json"])
        paths = [call.args[1] for call in request.call_args_list]
        self.assertTrue(any(path.endswith("/v1/secrets/by-key/versions?namespace=db01&key=user%3Asys&limit=10") for path in paths))
        self.assertTrue(any(path.endswith("/v1/secrets/by-key/access?namespace=db01&key=user%3Asys&limit=10") for path in paths))
        self.assertTrue(any(path.endswith("/v1/secrets/by-key/access/client_bob?namespace=db01&key=user%3Asys") for path in paths))
        self.assertEqual(request.call_args_list[-1].args[0], "DELETE")
        self.assertIn("/v1/secrets/by-key?namespace=db01&key=user%3Asys&cascade=true", request.call_args_list[-1].args[1])


if __name__ == "__main__":
    unittest.main()
