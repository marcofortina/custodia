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
			writeError(w, http.StatusUnauthorized, "missing_client_certificate")
			return
		}
		client, err := s.store.GetActiveClientBySubject(r.Context(), mtlsSubject)
		if err != nil {
			writeError(w, http.StatusForbidden, "client_not_authorized")
			return
		}
		if s.limiter != nil {
			allowed, err := s.limiter.Allow(r.Context(), "client:"+client.ClientID, s.clientRateLimit)
			if err != nil {
				writeError(w, http.StatusServiceUnavailable, "rate_limiter_unavailable")
				return
			}
			if !allowed {
				writeError(w, http.StatusTooManyRequests, "client_rate_limited")
				return
			}
			allowed, err = s.limiter.Allow(r.Context(), "global", s.globalRateLimit)
			if err != nil {
				writeError(w, http.StatusServiceUnavailable, "rate_limiter_unavailable")
				return
			}
			if !allowed {
				writeError(w, http.StatusTooManyRequests, "global_rate_limited")
				return
			}
		}
		ctx := context.WithValue(r.Context(), clientIDContextKey, client.ClientID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) adminOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientID := clientIDFromContext(r)
		if !s.adminClientIDs[clientID] {
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
