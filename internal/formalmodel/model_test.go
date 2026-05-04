// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package formalmodel

import "testing"

func TestRevokedClientCannotRead(t *testing.T) {
	state := NewState().AddClient("client_alice").GrantRead("client_alice", "secret_1", 1)
	if !state.CanRead("client_alice", "secret_1", 1) {
		t.Fatal("expected active client to read granted version")
	}
	state = state.RevokeClient("client_alice")
	if state.CanRead("client_alice", "secret_1", 1) {
		t.Fatal("revoked client can still read")
	}
	if err := state.CheckInvariants(); err != nil {
		t.Fatalf("CheckInvariants() error = %v", err)
	}
}

func TestStrongRevocationDropsOldVersions(t *testing.T) {
	state := NewState().AddClient("client_alice").GrantRead("client_alice", "secret_1", 1).GrantRead("client_alice", "secret_1", 2)
	state = state.StrongRevokeSecret("secret_1", 2)
	if state.CanRead("client_alice", "secret_1", 1) {
		t.Fatal("old version remained readable after strong revocation")
	}
	if !state.CanRead("client_alice", "secret_1", 2) {
		t.Fatal("active version should remain readable")
	}
	if err := state.CheckInvariants(); err != nil {
		t.Fatalf("CheckInvariants() error = %v", err)
	}
}

func TestInvariantDetectsRevokedClientGrant(t *testing.T) {
	state := NewState()
	state.Clients["client_alice"] = false
	state.Access[AccessKey{ClientID: "client_alice", SecretID: "secret_1", Version: 1}] = true
	if err := state.CheckInvariants(); err == nil {
		t.Fatal("expected invariant violation")
	}
}
