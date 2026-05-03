package httpapi

import (
	"custodia/internal/ratelimit"
	"custodia/internal/store"
	"custodia/internal/webauth"
	"net/http"
	"time"
)

type Server struct {
	store                  store.Store
	limiter                ratelimit.Limiter
	adminClientIDs         map[string]bool
	maxEnvelopesPerSecret  int
	clientRateLimit        int
	globalRateLimit        int
	ipRateLimit            int
	storeBackend           string
	rateLimitBackend       string
	startedAt              time.Time
	webMFARequired         bool
	webTOTPSecret          string
	webSessionManager      *webauth.SessionManager
	webSessionSecure       bool
	webPasskeyEnabled      bool
	webPasskeyRPID         string
	webPasskeyRPName       string
	webPasskeyChallengeTTL time.Duration
}

type Options struct {
	Store                  store.Store
	Limiter                ratelimit.Limiter
	AdminClientIDs         map[string]bool
	MaxEnvelopesPerSecret  int
	ClientRateLimit        int
	GlobalRateLimit        int
	IPRateLimit            int
	StoreBackend           string
	RateLimitBackend       string
	WebMFARequired         bool
	WebTOTPSecret          string
	WebSessionSecret       string
	WebSessionTTL          time.Duration
	WebSessionSecure       bool
	WebPasskeyEnabled      bool
	WebPasskeyRPID         string
	WebPasskeyRPName       string
	WebPasskeyChallengeTTL time.Duration
}

type contextKey string

const (
	clientIDContextKey           contextKey = "client_id"
	requestIDContextKey          contextKey = "request_id"
	DefaultMaxEnvelopesPerSecret            = 100
)

func New(options Options) http.Handler {
	maxEnvelopesPerSecret := options.MaxEnvelopesPerSecret
	if maxEnvelopesPerSecret <= 0 {
		maxEnvelopesPerSecret = DefaultMaxEnvelopesPerSecret
	}
	var webSessionManager *webauth.SessionManager
	if options.WebMFARequired {
		manager, err := webauth.NewSessionManager(options.WebSessionSecret, options.WebSessionTTL)
		if err == nil {
			webSessionManager = manager
		}
	}
	webPasskeyRPID := options.WebPasskeyRPID
	if webPasskeyRPID == "" {
		webPasskeyRPID = "localhost"
	}
	webPasskeyRPName := options.WebPasskeyRPName
	if webPasskeyRPName == "" {
		webPasskeyRPName = "Custodia"
	}
	webPasskeyChallengeTTL := options.WebPasskeyChallengeTTL
	if webPasskeyChallengeTTL <= 0 {
		webPasskeyChallengeTTL = 5 * time.Minute
	}
	server := &Server{
		store:                  options.Store,
		limiter:                options.Limiter,
		adminClientIDs:         options.AdminClientIDs,
		maxEnvelopesPerSecret:  maxEnvelopesPerSecret,
		clientRateLimit:        options.ClientRateLimit,
		globalRateLimit:        options.GlobalRateLimit,
		ipRateLimit:            options.IPRateLimit,
		storeBackend:           options.StoreBackend,
		rateLimitBackend:       options.RateLimitBackend,
		startedAt:              time.Now().UTC(),
		webMFARequired:         options.WebMFARequired,
		webTOTPSecret:          options.WebTOTPSecret,
		webSessionManager:      webSessionManager,
		webSessionSecure:       options.WebSessionSecure,
		webPasskeyEnabled:      options.WebPasskeyEnabled,
		webPasskeyRPID:         webPasskeyRPID,
		webPasskeyRPName:       webPasskeyRPName,
		webPasskeyChallengeTTL: webPasskeyChallengeTTL,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", server.handleHealth)
	mux.HandleFunc("GET /live", server.handleLive)
	mux.HandleFunc("GET /ready", server.handleReady)
	mux.Handle("GET /web/", server.auth(server.adminOnly(http.HandlerFunc(server.handleWeb))))
	mux.Handle("GET /web/status", server.auth(server.adminOnly(http.HandlerFunc(server.handleWebStatus))))
	mux.Handle("GET /web/diagnostics", server.auth(server.adminOnly(http.HandlerFunc(server.handleWebDiagnostics))))
	mux.Handle("GET /web/clients", server.auth(server.adminOnly(http.HandlerFunc(server.handleWebClients))))
	mux.Handle("GET /web/audit", server.auth(server.adminOnly(http.HandlerFunc(server.handleWebAudit))))
	mux.Handle("GET /web/audit/verify", server.auth(server.adminOnly(http.HandlerFunc(server.handleWebAuditVerify))))
	mux.Handle("GET /web/access-requests", server.auth(server.adminOnly(http.HandlerFunc(server.handleWebAccessRequests))))
	mux.Handle("GET /v1/me", server.auth(http.HandlerFunc(server.handleMe)))
	mux.Handle("GET /v1/clients", server.auth(server.adminOnly(http.HandlerFunc(server.handleListClients))))
	mux.Handle("GET /v1/clients/{client_id}", server.auth(server.adminOnly(http.HandlerFunc(server.handleGetClient))))
	mux.Handle("POST /v1/clients", server.auth(server.adminOnly(http.HandlerFunc(server.handleCreateClient))))
	mux.Handle("POST /v1/clients/revoke", server.auth(server.adminOnly(http.HandlerFunc(server.handleRevokeClient))))
	mux.Handle("GET /v1/status", server.auth(server.adminOnly(http.HandlerFunc(server.handleStatus))))
	mux.Handle("GET /v1/version", server.auth(server.adminOnly(http.HandlerFunc(server.handleVersion))))
	mux.Handle("GET /v1/diagnostics", server.auth(server.adminOnly(http.HandlerFunc(server.handleDiagnostics))))
	mux.Handle("GET /v1/access-requests", server.auth(server.adminOnly(http.HandlerFunc(server.handleListAccessGrantRequests))))
	mux.Handle("GET /v1/audit-events", server.auth(server.adminOnly(http.HandlerFunc(server.handleListAuditEvents))))
	mux.Handle("GET /v1/audit-events/export", server.auth(server.adminOnly(http.HandlerFunc(server.handleExportAuditEvents))))
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
	return requestIDs(securityHeaders(mux))
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
		next.ServeHTTP(w, r)
	})
}
