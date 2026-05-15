// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

// Package client is the Go SDK surface for Custodia clients.
//
// The package has two layers. Client is the transport layer: it sends and
// receives already-opaque REST payloads over mutual TLS and uses namespace/key
// workflow helpers for new integrations. CryptoClient is the high-level layer:
// it encrypts plaintext, creates recipient envelopes, decrypts authorized
// payloads and rewraps DEKs locally before calling the transport layer.
//
// Custodia servers remain metadata-only. Transport helpers may send ciphertext,
// crypto metadata and recipient envelopes, but plaintext, DEKs, private keys and
// private-key providers must stay in the caller process.
//
// The SDK source is currently distributed from this repository and from the
// custodia-sdk Linux package source snapshot. External registry publishing is
// gated by docs/SDK_PUBLISHING_READINESS.md.
package client
