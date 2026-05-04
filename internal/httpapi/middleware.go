// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package httpapi

import (
	"context"
	"net"
	"net/http"
	"strings"
	"time"
	"unicode"

	"custodia/internal/id"
	"custodia/internal/mtls"
	"custodia/internal/webauth"
)

func requestIDs(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := strings.TrimSpace(r.Header.Get("X-Request-ID"))
		if !validRequestID(requestID) {
			requestID = id.New()
		}
		w.Header().Set("X-Request-ID", requestID)
		ctx := context.WithValue(r.Context(), requestIDContextKey, requestID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func requestIDFromContext(r *http.Request) string {
	value, _ := r.Context().Value(requestIDContextKey).(string)
	return value
}

func validRequestID(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func (s *Server) webAdmin(next http.Handler) http.Handler {
	return s.auth(s.adminOnly(s.webMFA(next)))
}

// webMFA binds browser metadata access to the already-authenticated mTLS client identity.
// The web session never grants access for a different client_id than the certificate resolved by auth.
func (s *Server) webMFA(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.webMFARequired {
			next.ServeHTTP(w, r)
			return
		}
		if s.webSessionManager == nil {
			s.auditFailure(r, "web.mfa", "system", "", map[string]string{"reason": "mfa_not_configured"})
			writeError(w, http.StatusServiceUnavailable, "mfa_not_configured")
			return
		}
		cookie, err := r.Cookie(webauth.SessionCookieName)
		if err != nil {
			s.auditFailure(r, "web.mfa", "system", "", map[string]string{"reason": "mfa_required"})
			http.Redirect(w, r, "/web/login", http.StatusSeeOther)
			return
		}
		sessionClientID, ok := s.webSessionManager.Verify(cookie.Value, time.Now().UTC())
		if !ok || sessionClientID != clientIDFromContext(r) {
			s.auditFailure(r, "web.mfa", "system", "", map[string]string{"reason": "invalid_session"})
			http.Redirect(w, r, "/web/login", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// auth is the API trust boundary: it maps the mTLS subject to an active client before rate limits or handlers use client_id.
func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.limiter != nil && s.ipRateLimit > 0 {
			allowed, err := s.limiter.Allow(r.Context(), "ip:"+remoteIP(r), s.ipRateLimit)
			if err != nil {
				s.auditFailure(r, "auth.rate_limit", "client", "", map[string]string{"reason": "rate_limiter_unavailable", "scope": "ip"})
				writeError(w, http.StatusServiceUnavailable, "rate_limiter_unavailable")
				return
			}
			if !allowed {
				s.auditFailure(r, "auth.rate_limit", "client", "", map[string]string{"reason": "ip_rate_limited"})
				writeRateLimited(w, "ip_rate_limited")
				return
			}
		}
		mtlsSubject, err := mtls.ClientIDFromRequest(r)
		if err != nil {
			s.auditFailure(r, "auth.mtls", "client", "", map[string]string{"reason": "missing_client_certificate"})
			writeError(w, http.StatusUnauthorized, "missing_client_certificate")
			return
		}
		client, err := s.store.GetActiveClientBySubject(r.Context(), mtlsSubject)
		if err != nil {
			s.auditFailure(r, "auth.mtls", "client", "", map[string]string{"reason": "client_not_authorized", "mtls_subject": mtlsSubject})
			writeError(w, http.StatusForbidden, "client_not_authorized")
			return
		}
		ctx := context.WithValue(r.Context(), clientIDContextKey, client.ClientID)
		r = r.WithContext(ctx)
		if s.limiter != nil {
			allowed, err := s.limiter.Allow(r.Context(), "client:"+client.ClientID, s.clientRateLimit)
			if err != nil {
				s.auditFailure(r, "auth.rate_limit", "client", client.ClientID, map[string]string{"reason": "rate_limiter_unavailable", "scope": "client"})
				writeError(w, http.StatusServiceUnavailable, "rate_limiter_unavailable")
				return
			}
			if !allowed {
				s.auditFailure(r, "auth.rate_limit", "client", client.ClientID, map[string]string{"reason": "client_rate_limited"})
				writeRateLimited(w, "client_rate_limited")
				return
			}
			allowed, err = s.limiter.Allow(r.Context(), "global", s.globalRateLimit)
			if err != nil {
				s.auditFailure(r, "auth.rate_limit", "client", client.ClientID, map[string]string{"reason": "rate_limiter_unavailable", "scope": "global"})
				writeError(w, http.StatusServiceUnavailable, "rate_limiter_unavailable")
				return
			}
			if !allowed {
				s.auditFailure(r, "auth.rate_limit", "client", client.ClientID, map[string]string{"reason": "global_rate_limited"})
				writeRateLimited(w, "global_rate_limited")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) adminOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientID := clientIDFromContext(r)
		if !s.adminClientIDs[clientID] {
			s.auditFailure(r, "auth.admin", "client", clientID, map[string]string{"reason": "admin_required"})
			writeError(w, http.StatusForbidden, "admin_required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func clientIDFromContext(r *http.Request) string {
	value, _ := r.Context().Value(clientIDContextKey).(string)
	return value
}

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	if r.RemoteAddr != "" {
		return r.RemoteAddr
	}
	return "unknown"
}
