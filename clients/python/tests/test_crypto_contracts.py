from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from custodia_client import (  # noqa: E402
    ENVELOPE_SCHEME_HPKE_V1,
    StaticPrivateKeyProvider,
    StaticPublicKeyResolver,
    X25519PrivateKeyHandle,
    derive_x25519_recipient_public_key,
)


ALICE_PRIVATE_KEY = b"1" * 32


class PythonCryptoContractsTest(unittest.TestCase):
    def test_x25519_public_contracts_are_exported(self) -> None:
        handle = X25519PrivateKeyHandle("client_alice", ALICE_PRIVATE_KEY)
        provider = StaticPrivateKeyProvider(handle)
        public_key = derive_x25519_recipient_public_key("client_alice", ALICE_PRIVATE_KEY)
        resolver = StaticPublicKeyResolver({"client_alice": public_key})

        self.assertEqual(provider.current_private_key().client_id, "client_alice")
        self.assertEqual(provider.current_private_key().scheme, ENVELOPE_SCHEME_HPKE_V1)
        self.assertEqual(resolver.resolve_recipient_public_key("client_alice").scheme, ENVELOPE_SCHEME_HPKE_V1)
        self.assertEqual(len(resolver.resolve_recipient_public_key("client_alice").public_key), 32)


if __name__ == "__main__":
    unittest.main()
