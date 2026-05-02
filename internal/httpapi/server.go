package httpapi

import (
	"custodia/internal/ratelimit"
	"custodia/internal/store"
	"net/http"
)

type Server struct {
	store                 store.Store
	limiter               ratelimit.Limiter
	adminClientIDs        map[string]bool
	maxEnvelopesPerSecret int
	clientRateLimit       int
	globalRateLimit       int
}

type Options struct {
	Store                 store.Store
	Limiter               ratelimit.Limiter
	AdminClientIDs        map[string]bool
	MaxEnvelopesPerSecret int
	ClientRateLimit       int
	GlobalRateLimit       int
}

type contextKey string

const (
	clientIDContextKey           contextKey = "client_id"
	DefaultMaxEnvelopesPerSecret            = 100
)

func New(options Options) http.Handler {
	maxEnvelopesPerSecret := options.MaxEnvelopesPerSecret
	if maxEnvelopesPerSecret <= 0 {
		maxEnvelopesPerSecret = DefaultMaxEnvelopesPerSecret
	}
	server := &Server{
		store:                 options.Store,
		limiter:               options.Limiter,
		adminClientIDs:        options.AdminClientIDs,
		maxEnvelopesPerSecret: maxEnvelopesPerSecret,
		clientRateLimit:       options.ClientRateLimit,
		globalRateLimit:       options.GlobalRateLimit,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", server.handleHealth)
	mux.HandleFunc("GET /ready", server.handleReady)
	mux.Handle("GET /web/", server.auth(server.adminOnly(http.HandlerFunc(server.handleWeb))))
	mux.Handle("GET /v1/clients", server.auth(server.adminOnly(http.HandlerFunc(server.handleListClients))))
	mux.Handle("POST /v1/clients", server.auth(server.adminOnly(http.HandlerFunc(server.handleCreateClient))))
	mux.Handle("POST /v1/clients/revoke", server.auth(server.adminOnly(http.HandlerFunc(server.handleRevokeClient))))
	mux.Handle("GET /v1/audit-events", server.auth(server.adminOnly(http.HandlerFunc(server.handleListAuditEvents))))
	mux.Handle("GET /v1/audit-events/verify", server.auth(server.adminOnly(http.HandlerFunc(server.handleVerifyAuditEvents))))
	mux.Handle("POST /v1/secrets", server.auth(http.HandlerFunc(server.handleCreateSecret)))
	mux.Handle("GET /v1/secrets", server.auth(http.HandlerFunc(server.handleListSecrets)))
	mux.Handle("GET /v1/secrets/{secret_id}", server.auth(http.HandlerFunc(server.handleGetSecret)))
	mux.Handle("GET /v1/secrets/{secret_id}/versions", server.auth(http.HandlerFunc(server.handleListSecretVersions)))
	mux.Handle("GET /v1/secrets/{secret_id}/access", server.auth(http.HandlerFunc(server.handleListSecretAccess)))
	mux.Handle("DELETE /v1/secrets/{secret_id}", server.auth(http.HandlerFunc(server.handleDeleteSecret)))
	mux.Handle("POST /v1/secrets/{secret_id}/share", server.auth(http.HandlerFunc(server.handleShareSecret)))
	mux.Handle("POST /v1/secrets/{secret_id}/access-requests", server.auth(server.adminOnly(http.HandlerFunc(server.handleRequestAccessGrant))))
	mux.Handle("POST /v1/secrets/{secret_id}/access/{client_id}/activate", server.auth(http.HandlerFunc(server.handleActivateAccessGrant)))
	mux.Handle("DELETE /v1/secrets/{secret_id}/access/{client_id}", server.auth(http.HandlerFunc(server.handleRevokeAccess)))
	mux.Handle("POST /v1/secrets/{secret_id}/versions", server.auth(http.HandlerFunc(server.handleCreateSecretVersion)))
	return securityHeaders(mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
		next.ServeHTTP(w, r)
	})
}
