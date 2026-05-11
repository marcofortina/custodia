// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package httpapi

import (
	"bytes"
	"net/http"
	"strings"
	"sync"
	"time"

	"custodia/internal/ratelimit"
	"custodia/internal/store"
	"custodia/internal/webauth"
)

// Server owns the API and web metadata surface. Secret plaintext, DEKs and private crypto keys never enter this layer.
type Server struct {
	store                            store.Store
	limiter                          ratelimit.Limiter
	adminClientIDs                   map[string]bool
	maxEnvelopesPerSecret            int
	clientRateLimit                  int
	globalRateLimit                  int
	ipRateLimit                      int
	storeBackend                     string
	rateLimitBackend                 string
	clientCAFile                     string
	clientCRLFile                    string
	startedAt                        time.Time
	webMFARequired                   bool
	webTOTPSecret                    string
	webSessionManager                *webauth.SessionManager
	webSessionSecure                 bool
	webPasskeyEnabled                bool
	webPasskeyRPID                   string
	webPasskeyRPName                 string
	webPasskeyChallengeTTL           time.Duration
	webPasskeyChallenges             *webauth.PasskeyChallengeStore
	webPasskeyCredentials            *webauth.PasskeyCredentialStore
	webPasskeyAssertionVerifyCommand string
	deploymentMode                   string
	databaseHATarget                 string
	auditShipmentSink                string
	enrollmentServerURL              string
	signerURL                        string
	signerClientCertFile             string
	signerClientKeyFile              string
	signerCAFile                     string
	enrollmentMu                     sync.Mutex
	enrollmentTokens                 map[string]enrollmentToken
}

type Options struct {
	Store                            store.Store
	Limiter                          ratelimit.Limiter
	AdminClientIDs                   map[string]bool
	MaxEnvelopesPerSecret            int
	ClientRateLimit                  int
	GlobalRateLimit                  int
	IPRateLimit                      int
	StoreBackend                     string
	RateLimitBackend                 string
	ClientCAFile                     string
	ClientCRLFile                    string
	WebMFARequired                   bool
	WebTOTPSecret                    string
	WebSessionSecret                 string
	WebSessionTTL                    time.Duration
	WebSessionSecure                 bool
	WebPasskeyEnabled                bool
	WebPasskeyRPID                   string
	WebPasskeyRPName                 string
	WebPasskeyChallengeTTL           time.Duration
	WebPasskeyAssertionVerifyCommand string
	DeploymentMode                   string
	DatabaseHATarget                 string
	AuditShipmentSink                string
	EnrollmentServerURL              string
	SignerURL                        string
	SignerClientCertFile             string
	SignerClientKeyFile              string
	SignerCAFile                     string
}

type contextKey string

const (
	clientIDContextKey           contextKey = "client_id"
	requestIDContextKey          contextKey = "request_id"
	DefaultMaxEnvelopesPerSecret            = 100
)

// New wires routes with explicit auth wrappers so public health endpoints and protected /v1 or /web endpoints stay obvious.
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
		store:                            options.Store,
		limiter:                          options.Limiter,
		adminClientIDs:                   options.AdminClientIDs,
		maxEnvelopesPerSecret:            maxEnvelopesPerSecret,
		clientRateLimit:                  options.ClientRateLimit,
		globalRateLimit:                  options.GlobalRateLimit,
		ipRateLimit:                      options.IPRateLimit,
		storeBackend:                     options.StoreBackend,
		rateLimitBackend:                 options.RateLimitBackend,
		clientCAFile:                     options.ClientCAFile,
		clientCRLFile:                    options.ClientCRLFile,
		startedAt:                        time.Now().UTC(),
		webMFARequired:                   options.WebMFARequired,
		webTOTPSecret:                    options.WebTOTPSecret,
		webSessionManager:                webSessionManager,
		webSessionSecure:                 options.WebSessionSecure,
		webPasskeyEnabled:                options.WebPasskeyEnabled,
		webPasskeyRPID:                   webPasskeyRPID,
		webPasskeyRPName:                 webPasskeyRPName,
		webPasskeyChallengeTTL:           webPasskeyChallengeTTL,
		webPasskeyChallenges:             webauth.NewPasskeyChallengeStore(),
		webPasskeyCredentials:            webauth.NewPasskeyCredentialStore(),
		webPasskeyAssertionVerifyCommand: options.WebPasskeyAssertionVerifyCommand,
		deploymentMode:                   options.DeploymentMode,
		databaseHATarget:                 options.DatabaseHATarget,
		auditShipmentSink:                options.AuditShipmentSink,
		enrollmentServerURL:              options.EnrollmentServerURL,
		signerURL:                        options.SignerURL,
		signerClientCertFile:             options.SignerClientCertFile,
		signerClientKeyFile:              options.SignerClientKeyFile,
		signerCAFile:                     options.SignerCAFile,
		enrollmentTokens:                 make(map[string]enrollmentToken),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", server.handleHealth)
	mux.HandleFunc("GET /live", server.handleLive)
	mux.HandleFunc("GET /ready", server.handleReady)
	mux.HandleFunc("GET /favicon.ico", server.handleWebFavicon)
	mux.HandleFunc("GET /web/assets/favicon.svg", server.handleWebFavicon)
	mux.Handle("GET /web/login", server.auth(server.adminOnly(http.HandlerFunc(server.handleWebLogin))))
	mux.Handle("POST /web/login", server.auth(server.adminOnly(http.HandlerFunc(server.handleWebLogin))))
	mux.Handle("POST /web/logout", server.auth(server.adminOnly(http.HandlerFunc(server.handleWebLogout))))
	mux.Handle("GET /web/assets/console.js", server.auth(server.adminOnly(http.HandlerFunc(server.handleWebConsoleAsset))))
	mux.Handle("GET /web/assets/console.css", server.auth(server.adminOnly(http.HandlerFunc(server.handleWebConsoleAsset))))
	mux.Handle("GET /web/passkey/register/options", server.webAdmin(http.HandlerFunc(server.handleWebPasskeyRegisterOptions)))
	mux.Handle("POST /web/passkey/register/verify", server.webAdmin(http.HandlerFunc(server.handleWebPasskeyRegisterVerify)))
	mux.Handle("GET /web/passkey/authenticate/options", server.webAdmin(http.HandlerFunc(server.handleWebPasskeyAuthenticateOptions)))
	mux.Handle("POST /web/passkey/authenticate/verify", server.webAdmin(http.HandlerFunc(server.handleWebPasskeyAuthenticateVerify)))
	mux.Handle("GET /web/", server.webAdmin(http.HandlerFunc(server.handleWeb)))
	mux.Handle("GET /web/status", server.webAdmin(http.HandlerFunc(server.handleWebStatus)))
	mux.Handle("GET /web/diagnostics", server.webAdmin(http.HandlerFunc(server.handleWebDiagnostics)))
	mux.Handle("GET /web/clients", server.webAdmin(http.HandlerFunc(server.handleWebClients)))
	mux.Handle("GET /web/audit", server.webAdmin(http.HandlerFunc(server.handleWebAudit)))
	mux.Handle("GET /web/audit/verify", server.webAdmin(http.HandlerFunc(server.handleWebAuditVerify)))
	mux.Handle("GET /web/access-requests", server.webAdmin(http.HandlerFunc(server.handleWebAccessRequests)))
	mux.Handle("POST /v1/client-enrollments/claim", http.HandlerFunc(server.handleClientEnrollmentClaim))
	mux.Handle("POST /v1/client-enrollments", server.auth(server.adminOnly(http.HandlerFunc(server.handleCreateClientEnrollment))))
	mux.Handle("GET /v1/me", server.auth(http.HandlerFunc(server.handleMe)))
	mux.Handle("GET /v1/clients", server.auth(server.adminOnly(http.HandlerFunc(server.handleListClients))))
	mux.Handle("GET /v1/clients/{client_id}", server.auth(server.adminOnly(http.HandlerFunc(server.handleGetClient))))
	mux.Handle("POST /v1/clients", server.auth(server.adminOnly(http.HandlerFunc(server.handleCreateClient))))
	mux.Handle("POST /v1/clients/revoke", server.auth(server.adminOnly(http.HandlerFunc(server.handleRevokeClient))))
	mux.Handle("GET /v1/status", server.auth(server.adminOnly(http.HandlerFunc(server.handleStatus))))
	mux.Handle("GET /v1/version", server.auth(server.adminOnly(http.HandlerFunc(server.handleVersion))))
	mux.Handle("GET /v1/diagnostics", server.auth(server.adminOnly(http.HandlerFunc(server.handleDiagnostics))))
	mux.Handle("GET /v1/revocation/status", server.auth(server.adminOnly(http.HandlerFunc(server.handleRevocationStatus))))
	mux.Handle("GET /v1/access-requests", server.auth(server.adminOnly(http.HandlerFunc(server.handleListAccessGrantRequests))))
	mux.Handle("GET /v1/audit-events", server.auth(server.adminOnly(http.HandlerFunc(server.handleListAuditEvents))))
	mux.Handle("GET /v1/audit-events/export", server.auth(server.adminOnly(http.HandlerFunc(server.handleExportAuditEvents))))
	mux.Handle("GET /v1/audit-events/verify", server.auth(server.adminOnly(http.HandlerFunc(server.handleVerifyAuditEvents))))
	mux.Handle("POST /v1/secrets", server.auth(http.HandlerFunc(server.handleCreateSecret)))
	mux.Handle("GET /v1/secrets", server.auth(http.HandlerFunc(server.handleListSecrets)))
	mux.Handle("GET /v1/secrets/by-key", server.auth(http.HandlerFunc(server.handleGetSecretByKey)))
	mux.Handle("DELETE /v1/secrets/by-key", server.auth(http.HandlerFunc(server.handleDeleteSecretByKey)))
	mux.Handle("POST /v1/secrets/by-key/share", server.auth(http.HandlerFunc(server.handleShareSecretByKey)))
	mux.Handle("DELETE /v1/secrets/by-key/access/{client_id}", server.auth(http.HandlerFunc(server.handleRevokeAccessByKey)))
	mux.Handle("POST /v1/secrets/by-key/access-requests", server.auth(server.adminOnly(http.HandlerFunc(server.handleRequestAccessGrantByKey))))
	mux.Handle("POST /v1/secrets/by-key/access/{client_id}/activate", server.auth(http.HandlerFunc(server.handleActivateAccessGrantByKey)))
	mux.Handle("GET /v1/secrets/by-key/access", server.auth(http.HandlerFunc(server.handleListSecretAccessByKey)))
	mux.Handle("POST /v1/secrets/by-key/versions", server.auth(http.HandlerFunc(server.handleCreateSecretVersionByKey)))
	mux.Handle("GET /v1/secrets/by-key/versions", server.auth(http.HandlerFunc(server.handleListSecretVersionsByKey)))
	mux.Handle("GET /v1/secrets/{secret_id}", server.auth(http.HandlerFunc(server.handleGetSecret)))
	mux.Handle("GET /v1/secrets/{secret_id}/versions", server.auth(http.HandlerFunc(server.handleListSecretVersions)))
	mux.Handle("GET /v1/secrets/{secret_id}/access", server.auth(http.HandlerFunc(server.handleListSecretAccess)))
	mux.Handle("DELETE /v1/secrets/{secret_id}", server.auth(http.HandlerFunc(server.handleDeleteSecret)))
	mux.Handle("POST /v1/secrets/{secret_id}/share", server.auth(http.HandlerFunc(server.handleShareSecret)))
	mux.Handle("POST /v1/secrets/{secret_id}/access-requests", server.auth(server.adminOnly(http.HandlerFunc(server.handleRequestAccessGrant))))
	mux.Handle("POST /v1/secrets/{secret_id}/access/{client_id}/activate", server.auth(http.HandlerFunc(server.handleActivateAccessGrant)))
	mux.Handle("DELETE /v1/secrets/{secret_id}/access/{client_id}", server.auth(http.HandlerFunc(server.handleRevokeAccess)))
	mux.Handle("POST /v1/secrets/{secret_id}/versions", server.auth(http.HandlerFunc(server.handleCreateSecretVersion)))
	return requestIDs(securityHeaders(webConsoleMethodErrorPages(mux)))
}

type bufferedResponseWriter struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func newBufferedResponseWriter() *bufferedResponseWriter {
	return &bufferedResponseWriter{header: make(http.Header)}
}

func (w *bufferedResponseWriter) Header() http.Header {
	return w.header
}

func (w *bufferedResponseWriter) WriteHeader(statusCode int) {
	if w.status == 0 {
		w.status = statusCode
	}
}

func (w *bufferedResponseWriter) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.body.Write(data)
}

func webConsoleMethodErrorPages(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isWebHTMLPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		captured := newBufferedResponseWriter()
		next.ServeHTTP(captured, r)
		if captured.status == http.StatusMethodNotAllowed {
			writeWebStatusError(w, http.StatusMethodNotAllowed, "method_not_allowed")
			return
		}
		for key, values := range captured.header {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
		if captured.status != 0 {
			w.WriteHeader(captured.status)
		}
		_, _ = w.Write(captured.body.Bytes())
	})
}

// APIOnly keeps the API listener from exposing the web console when a dedicated
// web listener is configured.
func APIOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isWebPath(r.URL.Path) {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// WebOnly keeps the web listener from exposing API routes when a dedicated web
// listener is configured.
func WebOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isWebPath(r.URL.Path) {
			writeWebNotFoundPage(w, false)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isWebPath(path string) bool {
	return path == "/favicon.ico" || path == "/web" || strings.HasPrefix(path, "/web/")
}

func isWebHTMLPath(path string) bool {
	if !isWebPath(path) {
		return false
	}
	if path == "/favicon.ico" || strings.HasPrefix(path, "/web/assets/") || strings.HasPrefix(path, "/web/passkey/") {
		return false
	}
	return true
}

const apiContentSecurityPolicy = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
const webContentSecurityPolicy = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"

func setSecurityHeaders(w http.ResponseWriter, webSurface bool) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
	if webSurface {
		w.Header().Set("Content-Security-Policy", webContentSecurityPolicy)
		return
	}
	w.Header().Set("Content-Security-Policy", apiContentSecurityPolicy)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setSecurityHeaders(w, isWebPath(r.URL.Path))
		next.ServeHTTP(w, r)
	})
}
