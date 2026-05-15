/*
 * Copyright (c) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * This file is part of Custodia.
 * Custodia is distributed under the GNU Affero General Public License v3.0.
 * See the accompanying LICENSE file for details.
 */

use custodia_client::{
    build_canonical_aad, canonical_aad_sha256, decode_base64, encode_base64, metadata_v1,
    open_content_aes_256_gcm, open_hpke_v1_envelope, seal_content_aes_256_gcm,
    seal_hpke_v1_envelope, CanonicalAADInputs,
};
use serde_json::Value;
use std::fs;
use std::path::PathBuf;

fn vector(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/client-crypto/v1")
        .join(name);
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

fn aad_inputs(value: &Value, field: &str) -> CanonicalAADInputs {
    let aad = &value[field];
    CanonicalAADInputs {
        namespace: aad["namespace"].as_str().unwrap().to_string(),
        key: aad["key"].as_str().unwrap().to_string(),
        secret_version: aad["secret_version"].as_u64().unwrap() as u32,
    }
}

fn metadata_and_aad(value: &Value) -> (custodia_client::CryptoMetadata, Vec<u8>) {
    let nonce = decode_base64(value["content_nonce_b64"].as_str().unwrap()).unwrap();
    let inputs = aad_inputs(value, "aad_inputs");
    let metadata = metadata_v1(inputs.clone(), &nonce);
    let aad = build_canonical_aad(&metadata, &inputs).unwrap();
    (metadata, aad)
}

#[test]
fn canonical_aad_matches_shared_vectors() {
    for name in ["create_secret_single_recipient.json", "create_secret_multi_recipient.json"] {
        let value = vector(name);
        let (_metadata, aad) = metadata_and_aad(&value);

        assert_eq!(String::from_utf8(aad.clone()).unwrap(), value["canonical_aad"].as_str().unwrap());
        assert_eq!(canonical_aad_sha256(&aad), value["canonical_aad_sha256"].as_str().unwrap());
    }
}

#[test]
fn content_ciphertext_matches_shared_vectors() {
    for name in ["create_secret_single_recipient.json", "create_secret_multi_recipient.json"] {
        let value = vector(name);
        let (_metadata, aad) = metadata_and_aad(&value);
        let dek = decode_base64(value["content_dek_b64"].as_str().unwrap()).unwrap();
        let nonce = decode_base64(value["content_nonce_b64"].as_str().unwrap()).unwrap();
        let plaintext = decode_base64(value["plaintext_b64"].as_str().unwrap()).unwrap();
        let ciphertext = seal_content_aes_256_gcm(&dek, &nonce, &plaintext, &aad).unwrap();

        assert_eq!(encode_base64(&ciphertext), value["ciphertext"].as_str().unwrap());
        assert_eq!(open_content_aes_256_gcm(&dek, &nonce, &ciphertext, &aad).unwrap(), plaintext);
    }
}

#[test]
fn hpke_envelopes_match_shared_vectors() {
    let value = vector("create_secret_multi_recipient.json");
    let (_metadata, aad) = metadata_and_aad(&value);
    let dek = decode_base64(value["content_dek_b64"].as_str().unwrap()).unwrap();

    for envelope in value["envelopes"].as_array().unwrap() {
        let recipient_public_key = decode_base64(envelope["recipient_public_key_b64"].as_str().unwrap()).unwrap();
        let recipient_private_key = decode_base64(envelope["recipient_private_key_b64"].as_str().unwrap()).unwrap();
        let ephemeral_private_key = decode_base64(envelope["sender_ephemeral_private_key_b64"].as_str().unwrap()).unwrap();
        let sealed = seal_hpke_v1_envelope(&recipient_public_key, &ephemeral_private_key, &dek, &aad).unwrap();

        assert_eq!(encode_base64(&sealed), envelope["envelope"].as_str().unwrap());
        assert_eq!(open_hpke_v1_envelope(&recipient_private_key, &sealed, &aad).unwrap(), dek);
    }
}

#[test]
fn aad_mismatch_vector_fails_to_decrypt() {
    let value = vector("aad_mismatch_fails.json");
    let nonce = decode_base64(value["content_nonce_b64"].as_str().unwrap()).unwrap();
    let metadata = metadata_v1(aad_inputs(&value, "mismatch_aad_inputs"), &nonce);
    let mismatch_inputs = aad_inputs(&value, "mismatch_aad_inputs");
    let mismatch_aad = build_canonical_aad(&metadata, &mismatch_inputs).unwrap();
    let dek = decode_base64(value["content_dek_b64"].as_str().unwrap()).unwrap();
    let ciphertext = decode_base64(value["ciphertext"].as_str().unwrap()).unwrap();

    assert!(open_content_aes_256_gcm(&dek, &nonce, &ciphertext, &mismatch_aad).is_err());
}
