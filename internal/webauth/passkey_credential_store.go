package webauth

import (
	"errors"
	"strings"
	"sync"
	"time"
)

var ErrPasskeyCredentialNotFound = errors.New("passkey credential not found")

type PasskeyCredentialRecord struct {
	CredentialID string    `json:"credential_id"`
	ClientID     string    `json:"client_id"`
	CreatedAt    time.Time `json:"created_at"`
	LastUsedAt   time.Time `json:"last_used_at,omitempty"`
	SignCount    uint32    `json:"sign_count"`
}

type PasskeyCredentialStore struct {
	mu          sync.Mutex
	credentials map[string]PasskeyCredentialRecord
}

func NewPasskeyCredentialStore() *PasskeyCredentialStore {
	return &PasskeyCredentialStore{credentials: map[string]PasskeyCredentialRecord{}}
}

func (s *PasskeyCredentialStore) Register(record PasskeyCredentialRecord) bool {
	if s == nil || strings.TrimSpace(record.CredentialID) == "" || strings.TrimSpace(record.ClientID) == "" || record.CreatedAt.IsZero() {
		return false
	}
	record.CredentialID = strings.TrimSpace(record.CredentialID)
	record.ClientID = strings.TrimSpace(record.ClientID)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.credentials[record.CredentialID] = record
	return true
}

func (s *PasskeyCredentialStore) Get(credentialID, clientID string) (PasskeyCredentialRecord, error) {
	if s == nil {
		return PasskeyCredentialRecord{}, ErrPasskeyCredentialNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.credentials[strings.TrimSpace(credentialID)]
	if !ok || record.ClientID != strings.TrimSpace(clientID) {
		return PasskeyCredentialRecord{}, ErrPasskeyCredentialNotFound
	}
	return record, nil
}

func (s *PasskeyCredentialStore) Touch(credentialID, clientID string, now time.Time) (PasskeyCredentialRecord, error) {
	if s == nil || now.IsZero() {
		return PasskeyCredentialRecord{}, ErrPasskeyCredentialNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.credentials[strings.TrimSpace(credentialID)]
	if !ok || record.ClientID != strings.TrimSpace(clientID) {
		return PasskeyCredentialRecord{}, ErrPasskeyCredentialNotFound
	}
	record.LastUsedAt = now.UTC()
	s.credentials[record.CredentialID] = record
	return record, nil
}

func (s *PasskeyCredentialStore) TouchWithSignCount(credentialID, clientID string, signCount uint32, now time.Time) (PasskeyCredentialRecord, error) {
	if s == nil || now.IsZero() {
		return PasskeyCredentialRecord{}, ErrPasskeyCredentialNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.credentials[strings.TrimSpace(credentialID)]
	if !ok || record.ClientID != strings.TrimSpace(clientID) {
		return PasskeyCredentialRecord{}, ErrPasskeyCredentialNotFound
	}
	if err := ValidatePasskeySignCount(record.SignCount, signCount); err != nil {
		return PasskeyCredentialRecord{}, err
	}
	record.LastUsedAt = now.UTC()
	record.SignCount = signCount
	s.credentials[record.CredentialID] = record
	return record, nil
}

func (s *PasskeyCredentialStore) CountForClient(clientID string) int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for _, record := range s.credentials {
		if record.ClientID == strings.TrimSpace(clientID) {
			count++
		}
	}
	return count
}

func (s *PasskeyCredentialStore) Count() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.credentials)
}
