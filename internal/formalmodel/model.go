// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package formalmodel

import "fmt"

type State struct {
	Clients map[string]bool
	Access  map[AccessKey]bool
}

type AccessKey struct {
	ClientID string
	SecretID string
	Version  int
}

func NewState() State {
	return State{Clients: map[string]bool{}, Access: map[AccessKey]bool{}}
}

func (s State) AddClient(clientID string) State {
	next := s.clone()
	next.Clients[clientID] = true
	return next
}

func (s State) RevokeClient(clientID string) State {
	next := s.clone()
	next.Clients[clientID] = false
	for key := range next.Access {
		if key.ClientID == clientID {
			delete(next.Access, key)
		}
	}
	return next
}

func (s State) GrantRead(clientID, secretID string, version int) State {
	next := s.clone()
	if next.Clients[clientID] {
		next.Access[AccessKey{ClientID: clientID, SecretID: secretID, Version: version}] = true
	}
	return next
}

func (s State) RevokeRead(clientID, secretID string, version int) State {
	next := s.clone()
	delete(next.Access, AccessKey{ClientID: clientID, SecretID: secretID, Version: version})
	return next
}

func (s State) StrongRevokeSecret(secretID string, activeVersion int) State {
	next := s.clone()
	for key := range next.Access {
		if key.SecretID == secretID && key.Version != activeVersion {
			delete(next.Access, key)
		}
	}
	return next
}

func (s State) CanRead(clientID, secretID string, version int) bool {
	return s.Clients[clientID] && s.Access[AccessKey{ClientID: clientID, SecretID: secretID, Version: version}]
}

func (s State) CheckInvariants() error {
	for key := range s.Access {
		if !s.Clients[key.ClientID] {
			return fmt.Errorf("revoked client %s has access to %s/%d", key.ClientID, key.SecretID, key.Version)
		}
		if key.Version <= 0 {
			return fmt.Errorf("non-positive secret version in access grant: %d", key.Version)
		}
	}
	return nil
}

func (s State) clone() State {
	next := NewState()
	for key, value := range s.Clients {
		next.Clients[key] = value
	}
	for key, value := range s.Access {
		next.Access[key] = value
	}
	return next
}
