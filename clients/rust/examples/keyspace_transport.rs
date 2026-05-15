/*
 * Copyright (c) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * This file is part of Custodia.
 * Custodia is distributed under the GNU Affero General Public License v3.0.
 * See the accompanying LICENSE file for details.
 */

//! Keyspace transport example for opaque Rust client payloads.
//!
//! This example intentionally sends already-opaque ciphertext/envelope payloads.
//! Applications that want local encryption should use the high-level crypto
//! wrapper shown in `high_level_crypto.rs`.

use custodia_client::{CustodiaClient, CustodiaClientConfig, PERMISSION_ALL};
use serde_json::json;

fn main() -> custodia_client::Result<()> {
    let client = CustodiaClient::new(CustodiaClientConfig::new(
        "https://vault.example.internal:8443",
        "client_alice.crt",
        "client_alice.key",
        "ca.crt",
    ))?;

    let payload = json!({
        "namespace": "default",
        "key": "db/password",
        "ciphertext": "base64-ciphertext-owned-by-the-application",
        "crypto_metadata": {"format": "application-defined"},
        "envelopes": [
            {"client_id": "client_alice", "envelope": "base64-envelope-for-alice"}
        ],
        "permissions": PERMISSION_ALL
    });

    client.create_secret_payload(&payload)?;
    client.get_secret_payload_by_key("default", "db/password")?;
    client.list_secret_version_metadata_by_key("default", "db/password", Some(20))?;
    client.share_secret_payload_by_key(
        "default",
        "db/password",
        &json!({
            "target_client_id": "client_bob",
            "envelope": "base64-envelope-for-bob",
            "permissions": custodia_client::PERMISSION_READ
        }),
    )?;

    Ok(())
}
