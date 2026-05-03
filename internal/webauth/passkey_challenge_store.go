package webauth

import (
	"errors"
	"strings"
	"sync"
	"time"
)

var ErrPasskeyChallengeNotFound = errors.New("passkey challenge not found")

type PasskeyChallengeRecord struct {
	Challenge string
	ClientID  string
	Purpose   string
	ExpiresAt time.Time
}

type PasskeyChallengeStore struct {
	mu      sync.Mutex
	records map[string]PasskeyChallengeRecord
}

func NewPasskeyChallengeStore() *PasskeyChallengeStore {
	return &PasskeyChallengeStore{records: map[string]PasskeyChallengeRecord{}}
}

func (s *PasskeyChallengeStore) Store(record PasskeyChallengeRecord) bool {
	if s == nil || strings.TrimSpace(record.Challenge) == "" || strings.TrimSpace(record.ClientID) == "" || strings.TrimSpace(record.Purpose) == "" || record.ExpiresAt.IsZero() {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[record.Challenge] = record
	return true
}

func (s *PasskeyChallengeStore) Consume(challenge, clientID, purpose string, now time.Time) (PasskeyChallengeRecord, error) {
	if s == nil {
		return PasskeyChallengeRecord{}, ErrPasskeyChallengeNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[strings.TrimSpace(challenge)]
	if !ok {
		return PasskeyChallengeRecord{}, ErrPasskeyChallengeNotFound
	}
	delete(s.records, record.Challenge)
	if record.ClientID != strings.TrimSpace(clientID) || record.Purpose != strings.TrimSpace(purpose) || !now.UTC().Before(record.ExpiresAt.UTC()) {
		return PasskeyChallengeRecord{}, ErrPasskeyChallengeNotFound
	}
	return record, nil
}

func (s *PasskeyChallengeStore) Prune(now time.Time) int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for challenge, record := range s.records {
		if !now.UTC().Before(record.ExpiresAt.UTC()) {
			delete(s.records, challenge)
			removed++
		}
	}
	return removed
}
