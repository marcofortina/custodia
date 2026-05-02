package httpapi

import (
	"context"
	"net/http"

	"custodia/internal/mtls"
)

func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
				writeError(w, http.StatusTooManyRequests, "client_rate_limited")
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
				writeError(w, http.StatusTooManyRequests, "global_rate_limited")
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
