// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package webauth

import (
	"strings"
	"testing"
	"time"
)

func TestSessionManagerIssuesAndVerifiesToken(t *testing.T) {
	manager, err := NewSessionManager("01234567890123456789012345678901", time.Minute)
	if err != nil {
		t.Fatalf("NewSessionManager() error = %v", err)
	}
	token, expires := manager.Issue("admin", time.Unix(100, 0))
	subject, ok := manager.Verify(token, time.Unix(120, 0))
	if !ok || subject != "admin" {
		t.Fatalf("Verify() = %q %v", subject, ok)
	}
	if !expires.After(time.Unix(100, 0)) {
		t.Fatalf("expires = %s", expires)
	}
}

func TestSessionManagerRejectsTamperedOrExpiredToken(t *testing.T) {
	manager, err := NewSessionManager("01234567890123456789012345678901", time.Minute)
	if err != nil {
		t.Fatalf("NewSessionManager() error = %v", err)
	}
	token, _ := manager.Issue("admin", time.Unix(100, 0))
	if _, ok := manager.Verify(token+"x", time.Unix(120, 0)); ok {
		t.Fatal("expected tampered token to be rejected")
	}
	if _, ok := manager.Verify(token, time.Unix(200, 0)); ok {
		t.Fatal("expected expired token to be rejected")
	}
}

func TestSessionCookieFlags(t *testing.T) {
	value := CookieHeaderValue("token", time.Unix(100, 0), true)
	for _, expected := range []string{SessionCookieName + "=token", "HttpOnly", "SameSite=Strict", "Path=/web", "Secure"} {
		if !strings.Contains(value, expected) {
			t.Fatalf("cookie header %q missing %q", value, expected)
		}
	}
	if !strings.Contains(ExpiredCookieHeaderValue(false), "Max-Age=0") {
		t.Fatal("expected expired cookie header")
	}
}

func TestNewSessionManagerRejectsWeakConfig(t *testing.T) {
	if _, err := NewSessionManager("short", time.Minute); err == nil {
		t.Fatal("expected short session secret error")
	}
	if _, err := NewSessionManager("01234567890123456789012345678901", 0); err == nil {
		t.Fatal("expected invalid ttl error")
	}
}
