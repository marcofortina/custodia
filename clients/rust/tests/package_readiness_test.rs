/*
 * Copyright (c) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * This file is part of Custodia.
 * Custodia is distributed under the GNU Affero General Public License v3.0.
 * See the accompanying LICENSE file for details.
 */

use std::fs;
use std::path::PathBuf;

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_repo_file(relative: &str) -> String {
    fs::read_to_string(manifest_dir().join(relative)).unwrap()
}

#[test]
fn cargo_metadata_documents_crates_io_readiness() {
    let manifest = read_repo_file("Cargo.toml");

    assert!(manifest.contains("name = \"custodia-client\""));
    assert!(manifest.contains("version = \"0.0.0\""));
    assert!(manifest.contains("publish = false"));
    assert!(manifest.contains("license = \"AGPL-3.0-only\""));
    assert!(manifest.contains("readme = \"README.md\""));
    assert!(manifest.contains("repository = \"https://github.com/marcofortina/custodia\""));
    assert!(manifest.contains("documentation = \"https://github.com/marcofortina/custodia/blob/master/docs/RUST_CLIENT_SDK.md\""));
}

#[test]
fn examples_cover_transport_and_high_level_crypto_surfaces() {
    let transport = read_repo_file("examples/keyspace_transport.rs");
    let crypto = read_repo_file("examples/high_level_crypto.rs");

    assert!(transport.contains("create_secret_payload"));
    assert!(transport.contains("get_secret_payload_by_key"));
    assert!(transport.contains("share_secret_payload_by_key"));
    assert!(crypto.contains("create_encrypted_secret_by_key"));
    assert!(crypto.contains("read_decrypted_secret_by_key"));
    assert!(crypto.contains("share_encrypted_secret_by_key"));
    assert!(crypto.contains("Plaintext, DEKs and private keys stay local"));
}

#[test]
fn publishing_remains_documentation_gated() {
    let checklist = fs::read_to_string(manifest_dir().join("../../docs/SDK_PUBLISHING_READINESS.md")).unwrap();

    assert!(checklist.contains("Rust `Cargo.toml` has crate metadata, readme, repository and documentation links documented"));
    assert!(checklist.contains("make test-rust-client"));
    assert!(checklist.contains("Registry publishing commands are not added to automation"));
}
