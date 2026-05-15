# Copyright (c) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-only
#
# This file is part of Custodia.
# Custodia is distributed under the GNU Affero General Public License v3.0.
# See the accompanying LICENSE file for details.

from __future__ import annotations

import importlib.util
import sys
import tomllib
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import custodia_client  # noqa: E402

PYTHON_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[3]
PYPROJECT = PYTHON_ROOT / "pyproject.toml"
EXAMPLES = PYTHON_ROOT / "examples"


class _Response:
    content = b'{"ok":true}'
    text = '{"ok":true}'
    headers: dict[str, str] = {}

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict[str, bool]:
        return {"ok": True}


def _load_example(name: str):
    spec = importlib.util.spec_from_file_location(name, EXAMPLES / f"{name}.py")
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load example: {name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PythonPackageReadinessTest(unittest.TestCase):
    def test_package_import_surface_is_available(self) -> None:
        self.assertTrue(hasattr(custodia_client, "CustodiaClient"))
        self.assertTrue(hasattr(custodia_client, "CreateSecretPayload"))
        self.assertTrue(hasattr(custodia_client, "CryptoOptions"))
        self.assertTrue(hasattr(custodia_client, "StaticPublicKeyResolver"))

    def test_pyproject_metadata_documents_package_identity(self) -> None:
        metadata = tomllib.loads(PYPROJECT.read_text())["project"]
        self.assertEqual(metadata["name"], "custodia-client")
        self.assertEqual(metadata["license"], "AGPL-3.0-only")
        self.assertEqual(metadata["readme"], "README.md")
        self.assertIn("requests>=2.32.0", metadata["dependencies"])
        self.assertIn("cryptography>=42.0.0", metadata["dependencies"])
        urls = metadata["urls"]
        self.assertIn("Repository", urls)
        self.assertIn("Issues", urls)
        self.assertIn("Documentation", urls)

    def test_examples_compile_and_use_public_api(self) -> None:
        for path in sorted(EXAMPLES.glob("*.py")):
            compile(path.read_text(), str(path), "exec")

        with patch("custodia_client.requests.request", return_value=_Response()) as request:
            transport_example = _load_example("keyspace_transport")
            crypto_example = _load_example("high_level_crypto")

            self.assertEqual(transport_example.create_opaque_secret(), {"ok": True})
            self.assertEqual(crypto_example.create_encrypted_secret(), {"ok": True})

        self.assertEqual(len(request.call_args_list), 2)
        transport_payload = request.call_args_list[0].kwargs["json"]
        crypto_payload = request.call_args_list[1].kwargs["json"]
        self.assertEqual(transport_payload["namespace"], "db01")
        self.assertEqual(transport_payload["key"], "user:sys")
        self.assertEqual(crypto_payload["namespace"], "db01")
        self.assertEqual(crypto_payload["key"], "user:sys")
        self.assertNotIn("plaintext", transport_payload)
        self.assertNotIn("plaintext", crypto_payload)

    def test_registry_publish_remains_documentation_gated(self) -> None:
        readiness = (REPO_ROOT / "docs" / "SDK_PUBLISHING_READINESS.md").read_text()
        python_readme = (PYTHON_ROOT / "README.md").read_text()
        self.assertIn("#41", readiness)
        self.assertIn("No registry publishing is performed", python_readme)


if __name__ == "__main__":
    unittest.main()
