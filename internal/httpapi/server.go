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

func New(options Options) *http.ServeMux {
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
	mux.HandleFunc("GET /web/", server.handleWeb)
	mux.Handle("GET /v1/clients", server.auth(server.adminOnly(http.HandlerFunc(server.handleListClients))))
	mux.Handle("POST /v1/clients/revoke", server.auth(server.adminOnly(http.HandlerFunc(server.handleRevokeClient))))
	mux.Handle("POST /v1/secrets", server.auth(http.HandlerFunc(server.handleCreateSecret)))
	mux.Handle("GET /v1/secrets/{secret_id}", server.auth(http.HandlerFunc(server.handleGetSecret)))
	mux.Handle("DELETE /v1/secrets/{secret_id}", server.auth(http.HandlerFunc(server.handleDeleteSecret)))
	mux.Handle("POST /v1/secrets/{secret_id}/share", server.auth(http.HandlerFunc(server.handleShareSecret)))
	mux.Handle("DELETE /v1/secrets/{secret_id}/access/{client_id}", server.auth(http.HandlerFunc(server.handleRevokeAccess)))
	mux.Handle("POST /v1/secrets/{secret_id}/versions", server.auth(http.HandlerFunc(server.handleCreateSecretVersion)))
	return mux
}
