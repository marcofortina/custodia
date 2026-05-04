// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"custodia/internal/crldist"
	"custodia/internal/id"
	"custodia/internal/mtls"
	"custodia/internal/revocationresponder"
	"custodia/internal/signeraudit"
	"custodia/internal/signing"
)

type signerConfig struct {
	addr                string
	tlsCertFile         string
	tlsKeyFile          string
	clientCAFile        string
	caCertFile          string
	caKeyFile           string
	caKeyPassphraseFile string
	keyProvider         string
	pkcs11SignCommand   string
	adminSubjects       map[string]bool
	defaultTTLHours     int
	devInsecureHTTP     bool
	shutdownTimeout     time.Duration
	auditLogFile        string
	crlFile             string
}

type signerServer struct {
	signer          *signing.ClientCertificateSigner
	adminSubjects   map[string]bool
	defaultTTLHours int
	devInsecureHTTP bool
	audit           signeraudit.Recorder
	crlFile         string
}

func main() {
	cfg := loadConfig()
	clientSigner, err := signing.LoadClientCertificateSignerWithOptions(cfg.keyProvider, cfg.caCertFile, cfg.caKeyFile, cfg.pkcs11SignCommand, cfg.caKeyPassphraseFile)
	if err != nil {
		log.Fatalf("signer init failed: %v", err)
	}
	if len(cfg.adminSubjects) == 0 {
		log.Fatalf("at least one CUSTODIA_SIGNER_ADMIN_SUBJECTS entry is required")
	}
	auditRecorder, err := buildAuditRecorder(cfg.auditLogFile)
	if err != nil {
		log.Fatalf("signer audit init failed: %v", err)
	}
	defer auditRecorder.Close()
	handler := newSignerServer(clientSigner, cfg.adminSubjects, cfg.defaultTTLHours, cfg.devInsecureHTTP, auditRecorder, cfg.crlFile)
	httpServer := &http.Server{
		Addr:              cfg.addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	go func() {
		if cfg.devInsecureHTTP {
			log.Printf("starting insecure development signer on %s", cfg.addr)
			if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Fatalf("signer failed: %v", err)
			}
			return
		}
		if cfg.tlsCertFile == "" || cfg.tlsKeyFile == "" || cfg.clientCAFile == "" {
			log.Fatalf("signer mTLS is required unless CUSTODIA_SIGNER_DEV_INSECURE_HTTP=true")
		}
		tlsConfig, err := mtls.ServerTLSConfig(cfg.tlsCertFile, cfg.tlsKeyFile, cfg.clientCAFile)
		if err != nil {
			log.Fatalf("signer TLS config failed: %v", err)
		}
		httpServer.TLSConfig = tlsConfig
		log.Printf("starting mTLS signer on %s", cfg.addr)
		if err := httpServer.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("signer failed: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), cfg.shutdownTimeout)
	defer cancel()
	if err := httpServer.Shutdown(ctx); err != nil {
		log.Printf("signer graceful shutdown failed: %v", err)
	}
}

type contextKey string

const requestIDContextKey contextKey = "request_id"

func newSignerServer(clientSigner *signing.ClientCertificateSigner, adminSubjects map[string]bool, defaultTTLHours int, devInsecureHTTP bool, auditRecorder signeraudit.Recorder, crlFile string) http.Handler {
	if auditRecorder == nil {
		auditRecorder = signeraudit.NopRecorder{}
	}
	if defaultTTLHours <= 0 {
		defaultTTLHours = int(signing.DefaultClientCertificateTTL / time.Hour)
	}
	server := &signerServer{
		signer:          clientSigner,
		adminSubjects:   adminSubjects,
		defaultTTLHours: defaultTTLHours,
		devInsecureHTTP: devInsecureHTTP,
		audit:           auditRecorder,
		crlFile:         strings.TrimSpace(crlFile),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", server.handleHealth)
	mux.HandleFunc("GET /live", server.handleHealth)
	mux.HandleFunc("GET /v1/crl.pem", server.handleCRL)
	mux.HandleFunc("GET /v1/revocation/serial", server.handleRevocationSerialStatus)
	mux.HandleFunc("POST /v1/certificates/sign", server.handleSignClientCertificate)
	return requestIDs(securityHeaders(mux))
}

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
		if r < 32 || r == 127 {
			return false
		}
	}
	return true
}

func (s *signerServer) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *signerServer) handleCRL(w http.ResponseWriter, r *http.Request) {
	if s.crlFile == "" {
		s.record(r, "crl.read", "failure", s.actor(r), "", map[string]string{"reason": "crl_not_configured"})
		writeError(w, http.StatusNotFound, "crl_not_configured")
		return
	}
	payload, list, err := crldist.LoadPEM(s.crlFile)
	if err != nil {
		s.record(r, "crl.read", "failure", s.actor(r), "", map[string]string{"reason": "invalid_crl"})
		writeError(w, http.StatusServiceUnavailable, "invalid_crl")
		return
	}
	w.Header().Set("Content-Type", "application/pkix-crl")
	w.Header().Set("Cache-Control", "max-age=300, must-revalidate")
	w.Header().Set("X-Custodia-CRL-Revoked-Count", strconv.Itoa(len(list.RevokedCertificateEntries)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(payload)
	s.record(r, "crl.read", "success", s.actor(r), "", map[string]string{"revoked_count": strconv.Itoa(len(list.RevokedCertificateEntries))})
}

func (s *signerServer) handleRevocationSerialStatus(w http.ResponseWriter, r *http.Request) {
	if s.crlFile == "" {
		s.record(r, "revocation.serial_status", "failure", s.actor(r), "", map[string]string{"reason": "crl_not_configured"})
		writeError(w, http.StatusNotFound, "crl_not_configured")
		return
	}
	serialHex := strings.TrimSpace(r.URL.Query().Get("serial_hex"))
	if serialHex == "" {
		s.record(r, "revocation.serial_status", "failure", s.actor(r), "", map[string]string{"reason": "missing_serial_hex"})
		writeError(w, http.StatusBadRequest, "missing_serial_hex")
		return
	}
	_, list, err := crldist.LoadPEM(s.crlFile)
	if err != nil {
		s.record(r, "revocation.serial_status", "failure", s.actor(r), "", map[string]string{"reason": "invalid_crl"})
		writeError(w, http.StatusServiceUnavailable, "invalid_crl")
		return
	}
	status, err := revocationresponder.CheckCRL(list, serialHex)
	if err != nil {
		s.record(r, "revocation.serial_status", "failure", s.actor(r), serialHex, map[string]string{"reason": "invalid_serial_hex"})
		writeError(w, http.StatusBadRequest, "invalid_serial_hex")
		return
	}
	s.record(r, "revocation.serial_status", "success", s.actor(r), status.SerialHex, map[string]string{"status": status.Status})
	writeJSON(w, http.StatusOK, status)
}

func (s *signerServer) handleSignClientCertificate(w http.ResponseWriter, r *http.Request) {
	actor := s.actor(r)
	if !s.authorized(r) {
		s.record(r, "certificate.sign", "failure", actor, "", map[string]string{"reason": "admin_required"})
		writeError(w, http.StatusForbidden, "admin_required")
		return
	}
	if !strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/json") {
		s.record(r, "certificate.sign", "failure", actor, "", map[string]string{"reason": "unsupported_media_type"})
		writeError(w, http.StatusUnsupportedMediaType, "unsupported_media_type")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1024*1024)
	var req signing.SignClientCertificateRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		s.record(r, "certificate.sign", "failure", actor, "", map[string]string{"reason": "invalid_json"})
		s.record(r, "certificate.sign", "failure", actor, req.ClientID, map[string]string{"reason": "invalid_json"})
		writeError(w, http.StatusBadRequest, "invalid_json")
		return
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return
	}
	ttlHours := req.TTLHours
	if ttlHours == 0 {
		ttlHours = s.defaultTTLHours
	}
	res, err := s.signer.SignClientCSR([]byte(req.CSRPem), req.ClientID, time.Duration(ttlHours)*time.Hour, time.Now().UTC())
	if err != nil {
		s.record(r, "certificate.sign", "failure", actor, req.ClientID, map[string]string{"reason": "invalid_csr"})
		writeError(w, http.StatusBadRequest, "invalid_csr")
		return
	}
	s.record(r, "certificate.sign", "success", actor, req.ClientID, nil)
	writeJSON(w, http.StatusCreated, res)
}

func (s *signerServer) actor(r *http.Request) string {
	if s.devInsecureHTTP {
		return strings.TrimSpace(r.Header.Get("X-Custodia-Signer-Admin-Subject"))
	}
	subject, err := mtls.ClientIDFromRequest(r)
	if err != nil {
		return ""
	}
	return subject
}

func (s *signerServer) record(r *http.Request, action, outcome, actor, clientID string, metadata map[string]string) {
	if s.audit == nil {
		return
	}
	_ = s.audit.Record(signeraudit.Event{
		OccurredAt: time.Now().UTC(),
		Action:     action,
		Outcome:    outcome,
		Actor:      actor,
		ClientID:   clientID,
		RequestID:  requestIDFromContext(r),
		Metadata:   metadata,
	})
}

func (s *signerServer) authorized(r *http.Request) bool {
	if s.devInsecureHTTP {
		return s.adminSubjects[strings.TrimSpace(r.Header.Get("X-Custodia-Signer-Admin-Subject"))]
	}
	subject, err := mtls.ClientIDFromRequest(r)
	return err == nil && s.adminSubjects[subject]
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}

func loadConfig() signerConfig {
	return signerConfig{
		addr:                env("CUSTODIA_SIGNER_ADDR", ":9444"),
		tlsCertFile:         os.Getenv("CUSTODIA_SIGNER_TLS_CERT_FILE"),
		tlsKeyFile:          os.Getenv("CUSTODIA_SIGNER_TLS_KEY_FILE"),
		clientCAFile:        os.Getenv("CUSTODIA_SIGNER_CLIENT_CA_FILE"),
		caCertFile:          os.Getenv("CUSTODIA_SIGNER_CA_CERT_FILE"),
		caKeyFile:           os.Getenv("CUSTODIA_SIGNER_CA_KEY_FILE"),
		caKeyPassphraseFile: os.Getenv("CUSTODIA_SIGNER_CA_KEY_PASSPHRASE_FILE"),
		keyProvider:         env("CUSTODIA_SIGNER_KEY_PROVIDER", signing.KeyProviderFile),
		pkcs11SignCommand:   os.Getenv("CUSTODIA_SIGNER_PKCS11_SIGN_COMMAND"),
		adminSubjects:       envSet("CUSTODIA_SIGNER_ADMIN_SUBJECTS"),
		defaultTTLHours:     envInt("CUSTODIA_SIGNER_DEFAULT_TTL_HOURS", int(signing.DefaultClientCertificateTTL/time.Hour)),
		devInsecureHTTP:     envBool("CUSTODIA_SIGNER_DEV_INSECURE_HTTP", false),
		shutdownTimeout:     time.Duration(envInt("CUSTODIA_SIGNER_SHUTDOWN_TIMEOUT_SECONDS", 10)) * time.Second,
		auditLogFile:        os.Getenv("CUSTODIA_SIGNER_AUDIT_LOG_FILE"),
		crlFile:             os.Getenv("CUSTODIA_SIGNER_CRL_FILE"),
	}
}

func buildAuditRecorder(path string) (signeraudit.Recorder, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return signeraudit.NopRecorder{}, nil
	}
	return signeraudit.NewJSONLRecorder(path)
}

func env(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func envInt(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

func envBool(key string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func envSet(key string) map[string]bool {
	set := make(map[string]bool)
	for _, part := range strings.Split(os.Getenv(key), ",") {
		value := strings.TrimSpace(part)
		if value != "" {
			set[value] = true
		}
	}
	return set
}
