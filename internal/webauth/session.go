// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package webauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const SessionCookieName = "custodia_web_session"

var ErrInvalidSession = errors.New("invalid web session")

type SessionManager struct {
	key []byte
	ttl time.Duration
}

// NewSessionManager requires an operator-provided secret rather than deriving one
// from process state, keeping web sessions stable across stateless replicas.
func NewSessionManager(secret string, ttl time.Duration) (*SessionManager, error) {
	secret = strings.TrimSpace(secret)
	if len(secret) < 32 {
		return nil, ErrInvalidSession
	}
	if ttl <= 0 {
		return nil, ErrInvalidSession
	}
	return &SessionManager{key: []byte(secret), ttl: ttl}, nil
}

func GenerateSessionSecret() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func (m *SessionManager) Issue(subject string, now time.Time) (string, time.Time) {
	subject = strings.TrimSpace(subject)
	expires := now.UTC().Add(m.ttl)
	payload := subject + "|" + strconv.FormatInt(expires.Unix(), 10)
	signature := m.sign(payload)
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + signature, expires
}

// Verify compares the HMAC before parsing trusted fields, so tampered payloads
// never influence subject or expiry handling.
func (m *SessionManager) Verify(token string, now time.Time) (string, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return "", false
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", false
	}
	payload := string(payloadBytes)
	if !hmac.Equal([]byte(m.sign(payload)), []byte(parts[1])) {
		return "", false
	}
	fields := strings.Split(payload, "|")
	if len(fields) != 2 || strings.TrimSpace(fields[0]) == "" {
		return "", false
	}
	expiresUnix, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return "", false
	}
	if !now.UTC().Before(time.Unix(expiresUnix, 0)) {
		return "", false
	}
	return fields[0], true
}

func (m *SessionManager) sign(payload string) string {
	mac := hmac.New(sha256.New, m.key)
	_, _ = mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func CookieHeaderValue(token string, expires time.Time, secure bool) string {
	flags := "HttpOnly; SameSite=Strict; Path=/web; Expires=" + expires.UTC().Format(time.RFC1123)
	if secure {
		flags += "; Secure"
	}
	return fmt.Sprintf("%s=%s; %s", SessionCookieName, token, flags)
}

func ExpiredCookieHeaderValue(secure bool) string {
	flags := "HttpOnly; SameSite=Strict; Path=/web; Max-Age=0"
	if secure {
		flags += "; Secure"
	}
	return fmt.Sprintf("%s=; %s", SessionCookieName, flags)
}
