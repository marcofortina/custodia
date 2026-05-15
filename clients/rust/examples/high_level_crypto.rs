/*
 * Copyright (c) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * This file is part of Custodia.
 * Custodia is distributed under the GNU Affero General Public License v3.0.
 * See the accompanying LICENSE file for details.
 */

//! High-level Rust crypto example.
//!
//! Plaintext, DEKs and private keys stay local to the caller. Custodia receives
//! only ciphertext, crypto metadata and opaque recipient envelopes.

use custodia_client::{
    derive_x25519_recipient_public_key, CustodiaClient, CustodiaClientConfig,
    CryptoOptions, StaticPrivateKeyProvider, StaticPublicKeyResolver,
    X25519PrivateKeyHandle, PERMISSION_ALL, PERMISSION_READ, X25519_KEY_BYTES,
};
use std::collections::BTreeMap;
use std::sync::Arc;

fn main() -> custodia_client::Result<()> {
    let client = CustodiaClient::new(CustodiaClientConfig::new(
        "https://vault.example.internal:8443",
        "client_alice.crt",
        "client_alice.key",
        "ca.crt",
    ))?;

    let alice_private_key = [0x11u8; X25519_KEY_BYTES];
    let bob_private_key = [0x22u8; X25519_KEY_BYTES];
    let charlie_private_key = [0x33u8; X25519_KEY_BYTES];

    let mut public_keys = BTreeMap::new();
    public_keys.insert(
        "client_alice".to_string(),
        derive_x25519_recipient_public_key("client_alice", &alice_private_key)?,
    );
    public_keys.insert(
        "client_bob".to_string(),
        derive_x25519_recipient_public_key("client_bob", &bob_private_key)?,
    );
    public_keys.insert(
        "client_charlie".to_string(),
        derive_x25519_recipient_public_key("client_charlie", &charlie_private_key)?,
    );

    let private_key = Arc::new(X25519PrivateKeyHandle::new("client_alice", &alice_private_key)?);
    let crypto = client.with_crypto(CryptoOptions::new(
        Arc::new(StaticPublicKeyResolver::new(public_keys)),
        Arc::new(StaticPrivateKeyProvider::new(private_key)),
    ));

    crypto.create_encrypted_secret_by_key(
        "default",
        "db/password",
        b"local plaintext never sent to Custodia",
        &["client_bob".to_string()],
        PERMISSION_ALL,
        None,
    )?;

    let decrypted = crypto.read_decrypted_secret_by_key("default", "db/password")?;
    let _local_plaintext = decrypted.plaintext;

    crypto.share_encrypted_secret_by_key(
        "default",
        "db/password",
        "client_charlie",
        PERMISSION_READ,
        None,
    )?;

    Ok(())
}
