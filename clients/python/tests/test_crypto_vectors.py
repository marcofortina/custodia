from __future__ import annotations

import base64
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from custodia_client.crypto import (  # noqa: E402
    CanonicalAADInputs,
    CiphertextAuthenticationFailed,
    CryptoMetadata,
    UnsupportedCryptoVersion,
    WrongRecipient,
    build_canonical_aad,
    canonical_aad_sha256,
    derive_x25519_public_key,
    open_content_aes_256_gcm,
    open_hpke_v1_envelope,
    seal_content_aes_256_gcm,
    seal_hpke_v1_envelope,
)


VECTOR_DIR = Path(__file__).resolve().parents[3] / "testdata" / "client-crypto" / "v1"


def _vector(name: str) -> dict[str, object]:
    return json.loads((VECTOR_DIR / name).read_text())


def _b64(value: str) -> bytes:
    return base64.b64decode(value)


class PythonCryptoVectorTest(unittest.TestCase):
    def test_canonical_aad_matches_vectors(self) -> None:
        for path in sorted(VECTOR_DIR.glob("*.json")):
            if path.name == "schema.json":
                continue
            vector = json.loads(path.read_text())
            if vector.get("expected_error") == "unsupported_crypto_version":
                with self.assertRaises(UnsupportedCryptoVersion):
                    build_canonical_aad(
                        CryptoMetadata.from_mapping(vector["crypto_metadata"]),
                        CanonicalAADInputs.from_mapping(vector.get("aad_inputs")),
                    )
                continue
            aad = build_canonical_aad(
                CryptoMetadata.from_mapping(vector["crypto_metadata"]),
                CanonicalAADInputs.from_mapping(vector.get("aad_inputs")),
            )
            self.assertEqual(aad.decode(), vector["canonical_aad"])
            self.assertEqual(canonical_aad_sha256(aad), vector["canonical_aad_sha256"])

    def test_content_ciphertext_matches_vectors(self) -> None:
        for name in [
            "create_secret_single_recipient.json",
            "create_secret_multi_recipient.json",
            "read_secret_authorized_recipient.json",
            "share_secret_add_recipient.json",
        ]:
            vector = _vector(name)
            aad = build_canonical_aad(
                CryptoMetadata.from_mapping(vector["crypto_metadata"]),
                CanonicalAADInputs.from_mapping(vector["aad_inputs"]),
            )
            ciphertext = seal_content_aes_256_gcm(
                _b64(vector["content_dek_b64"]),
                _b64(vector["content_nonce_b64"]),
                _b64(vector["plaintext_b64"]),
                aad,
            )
            self.assertEqual(base64.b64encode(ciphertext).decode(), vector["ciphertext"])
            self.assertEqual(
                open_content_aes_256_gcm(_b64(vector["content_dek_b64"]), _b64(vector["content_nonce_b64"]), ciphertext, aad),
                _b64(vector["plaintext_b64"]),
            )

    def test_envelopes_match_vectors(self) -> None:
        for name in [
            "create_secret_single_recipient.json",
            "create_secret_multi_recipient.json",
            "read_secret_authorized_recipient.json",
            "share_secret_add_recipient.json",
        ]:
            vector = _vector(name)
            aad = build_canonical_aad(
                CryptoMetadata.from_mapping(vector["crypto_metadata"]),
                CanonicalAADInputs.from_mapping(vector["aad_inputs"]),
            )
            envelopes = vector.get("envelopes") or [vector["envelope"]]
            for envelope in envelopes:
                self.assertEqual(derive_x25519_public_key(_b64(envelope["recipient_private_key_b64"])), _b64(envelope["recipient_public_key_b64"]))
                sealed = seal_hpke_v1_envelope(
                    _b64(envelope["recipient_public_key_b64"]),
                    _b64(envelope["sender_ephemeral_private_key_b64"]),
                    _b64(vector["content_dek_b64"]),
                    aad,
                )
                self.assertEqual(base64.b64encode(sealed).decode(), envelope["envelope"])
                self.assertEqual(open_hpke_v1_envelope(_b64(envelope["recipient_private_key_b64"]), sealed, aad), _b64(vector["content_dek_b64"]))

    def test_negative_vectors_fail(self) -> None:
        tampered = _vector("tamper_ciphertext_fails.json")
        aad = build_canonical_aad(
            CryptoMetadata.from_mapping(tampered["crypto_metadata"]),
            CanonicalAADInputs.from_mapping(tampered["aad_inputs"]),
        )
        envelope = tampered["envelope"]
        dek = open_hpke_v1_envelope(_b64(envelope["recipient_private_key_b64"]), _b64(envelope["envelope"]), aad)
        with self.assertRaises(CiphertextAuthenticationFailed):
            open_content_aes_256_gcm(dek, _b64(tampered["content_nonce_b64"]), _b64(tampered["tampered_ciphertext"]), aad)

        wrong = _vector("wrong_recipient_fails.json")
        envelope = wrong["envelope"]
        with self.assertRaises(WrongRecipient):
            open_hpke_v1_envelope(_b64(envelope["wrong_recipient_private_key_b64"]), _b64(envelope["envelope"]), aad)

        mismatch = _vector("aad_mismatch_fails.json")
        mismatch_aad = build_canonical_aad(
            CryptoMetadata.from_mapping(mismatch["crypto_metadata"]),
            CanonicalAADInputs.from_mapping(mismatch["mismatch_aad_inputs"]),
        )
        envelope = mismatch["envelope"]
        with self.assertRaises(WrongRecipient):
            open_hpke_v1_envelope(_b64(envelope["recipient_private_key_b64"]), _b64(envelope["envelope"]), mismatch_aad)


if __name__ == "__main__":
    unittest.main()
