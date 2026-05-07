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
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"custodia/internal/build"
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

// signerServer owns only certificate lifecycle operations. It never participates
// in application-secret encryption, which remains entirely client-side.
type signerServer struct {
	signer          *signing.ClientCertificateSigner
	adminSubjects   map[string]bool
	defaultTTLHours int
	devInsecureHTTP bool
	audit           signeraudit.Recorder
	crlFile         string
}

func main() {
	if handled, code := handleInfoCommand(os.Args[1:], os.Stdout); handled {
		os.Exit(code)
	}
	cfg, err := loadConfigWithArgs(os.Args[1:])
	if err != nil {
		log.Fatalf("config load failed: %v", err)
	}
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

const signerUsage = `Usage:
  custodia-signer [--config FILE]
  custodia-signer version
  custodia-signer --version
  custodia-signer help

Runs the Custodia CA signer service. Runtime configuration is loaded from
profile defaults, an optional flat YAML config file, then CUSTODIA_SIGNER_*
environment overrides.
`

func handleInfoCommand(args []string, stdout io.Writer) (bool, int) {
	if len(args) != 1 {
		return false, 0
	}
	switch strings.TrimSpace(args[0]) {
	case "version", "--version", "-version":
		info := build.Current()
		fmt.Fprintf(stdout, "%s %s %s\n", info.Version, info.Commit, info.Date)
		return true, 0
	case "help", "--help", "-h":
		fmt.Fprint(stdout, signerUsage)
		return true, 0
	default:
		return false, 0
	}
}

type contextKey string

const requestIDContextKey contextKey = "request_id"

// newSignerServer exposes a deliberately small API surface: health, CRL/status,
// and CSR signing. Narrow routing reduces CA-key exposure in production.
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

// requestIDs accepts a safe upstream request id when present and otherwise
// generates one, so signer audit records can be correlated without trusting input.
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

// handleSignClientCertificate is the CA boundary: caller identity is mTLS admin
// subject, while the CSR subject is validated separately by the signer package.
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
	cfg, err := loadConfigWithArgs(nil)
	if err != nil {
		return signerDefaults()
	}
	return cfg
}

func loadConfigWithArgs(args []string) (signerConfig, error) {
	configFile, err := parseSignerConfigArgs(args)
	if err != nil {
		return signerConfig{}, err
	}
	cfg := signerDefaults()
	if configFile != "" {
		values, err := loadSignerSimpleYAML(configFile)
		if err != nil {
			return signerConfig{}, err
		}
		if err := applySignerValues(&cfg, values); err != nil {
			return signerConfig{}, err
		}
	}
	applySignerEnv(&cfg)
	return cfg, nil
}

func signerDefaults() signerConfig {
	return signerConfig{
		addr:            ":9444",
		keyProvider:     signing.KeyProviderFile,
		adminSubjects:   map[string]bool{},
		defaultTTLHours: int(signing.DefaultClientCertificateTTL / time.Hour),
		shutdownTimeout: 10 * time.Second,
	}
}

func parseSignerConfigArgs(args []string) (string, error) {
	for index := 0; index < len(args); index++ {
		arg := strings.TrimSpace(args[index])
		if arg == "--config" {
			if index+1 >= len(args) || strings.TrimSpace(args[index+1]) == "" {
				return "", errors.New("--config requires a path")
			}
			return strings.TrimSpace(args[index+1]), nil
		}
		if strings.HasPrefix(arg, "--config=") {
			value := strings.TrimSpace(strings.TrimPrefix(arg, "--config="))
			if value == "" {
				return "", errors.New("--config requires a path")
			}
			return value, nil
		}
	}
	return "", nil
}

func applySignerEnv(cfg *signerConfig) {
	setStringEnv(&cfg.addr, "CUSTODIA_SIGNER_ADDR")
	setStringEnv(&cfg.tlsCertFile, "CUSTODIA_SIGNER_TLS_CERT_FILE")
	setStringEnv(&cfg.tlsKeyFile, "CUSTODIA_SIGNER_TLS_KEY_FILE")
	setStringEnv(&cfg.clientCAFile, "CUSTODIA_SIGNER_CLIENT_CA_FILE")
	setStringEnv(&cfg.caCertFile, "CUSTODIA_SIGNER_CA_CERT_FILE")
	setStringEnv(&cfg.caKeyFile, "CUSTODIA_SIGNER_CA_KEY_FILE")
	setStringEnv(&cfg.caKeyPassphraseFile, "CUSTODIA_SIGNER_CA_KEY_PASSPHRASE_FILE")
	setStringEnv(&cfg.keyProvider, "CUSTODIA_SIGNER_KEY_PROVIDER")
	setStringEnv(&cfg.pkcs11SignCommand, "CUSTODIA_SIGNER_PKCS11_SIGN_COMMAND")
	setStringEnv(&cfg.auditLogFile, "CUSTODIA_SIGNER_AUDIT_LOG_FILE")
	setStringEnv(&cfg.crlFile, "CUSTODIA_SIGNER_CRL_FILE")
	if value := strings.TrimSpace(os.Getenv("CUSTODIA_SIGNER_ADMIN_SUBJECTS")); value != "" {
		cfg.adminSubjects = parseSubjectSet(value)
	}
	if value, ok := parsePositiveEnvInt("CUSTODIA_SIGNER_DEFAULT_TTL_HOURS"); ok {
		cfg.defaultTTLHours = value
	}
	if value, ok := parseEnvBool("CUSTODIA_SIGNER_DEV_INSECURE_HTTP"); ok {
		cfg.devInsecureHTTP = value
	}
	if value, ok := parsePositiveEnvInt("CUSTODIA_SIGNER_SHUTDOWN_TIMEOUT_SECONDS"); ok {
		cfg.shutdownTimeout = time.Duration(value) * time.Second
	}
}

func applySignerValues(cfg *signerConfig, values map[string]string) error {
	for key, value := range values {
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "addr":
			cfg.addr = value
		case "tls_cert_file":
			cfg.tlsCertFile = value
		case "tls_key_file":
			cfg.tlsKeyFile = value
		case "client_ca_file":
			cfg.clientCAFile = value
		case "ca_cert_file":
			cfg.caCertFile = value
		case "ca_key_file":
			cfg.caKeyFile = value
		case "ca_key_passphrase_file":
			cfg.caKeyPassphraseFile = value
		case "key_provider":
			cfg.keyProvider = value
		case "pkcs11_sign_command":
			cfg.pkcs11SignCommand = value
		case "admin_subjects":
			cfg.adminSubjects = parseSubjectSet(value)
		case "default_ttl_hours":
			parsed, err := parsePositiveInt(value)
			if err != nil {
				return fmt.Errorf("default_ttl_hours: %w", err)
			}
			cfg.defaultTTLHours = parsed
		case "dev_insecure_http":
			parsed, err := strconv.ParseBool(value)
			if err != nil {
				return fmt.Errorf("dev_insecure_http: %w", err)
			}
			cfg.devInsecureHTTP = parsed
		case "shutdown_timeout_seconds":
			parsed, err := parsePositiveInt(value)
			if err != nil {
				return fmt.Errorf("shutdown_timeout_seconds: %w", err)
			}
			cfg.shutdownTimeout = time.Duration(parsed) * time.Second
		case "audit_log_file":
			cfg.auditLogFile = value
		case "crl_file":
			cfg.crlFile = value
		default:
			return fmt.Errorf("unknown signer config key %q", key)
		}
	}
	return nil
}

func buildAuditRecorder(path string) (signeraudit.Recorder, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return signeraudit.NopRecorder{}, nil
	}
	return signeraudit.NewJSONLRecorder(path)
}

func setStringEnv(target *string, key string) {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		*target = value
	}
}

func parsePositiveEnvInt(key string) (int, bool) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return 0, false
	}
	parsed, err := parsePositiveInt(value)
	if err != nil {
		return 0, false
	}
	return parsed, true
}

func parseEnvBool(key string) (bool, bool) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return false, false
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, false
	}
	return parsed, true
}

func parsePositiveInt(value string) (int, error) {
	parsed, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || parsed <= 0 {
		return 0, fmt.Errorf("must be a positive integer")
	}
	return parsed, nil
}

func parseSubjectSet(value string) map[string]bool {
	set := make(map[string]bool)
	for _, part := range strings.Split(value, ",") {
		entry := strings.TrimSpace(part)
		if entry != "" {
			set[entry] = true
		}
	}
	return set
}

func loadSignerSimpleYAML(path string) (map[string]string, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	values := make(map[string]string)
	for lineNumber, raw := range strings.Split(string(payload), "\n") {
		line := strings.TrimSpace(stripSignerComment(raw))
		if line == "" || line == "---" {
			continue
		}
		if strings.HasPrefix(line, "-") || strings.HasSuffix(line, ":") {
			return nil, fmt.Errorf("unsupported YAML syntax on line %d", lineNumber+1)
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok || strings.TrimSpace(key) == "" {
			return nil, fmt.Errorf("invalid YAML line %d", lineNumber+1)
		}
		values[strings.TrimSpace(key)] = unquoteSignerValue(strings.TrimSpace(value))
	}
	return values, nil
}

func stripSignerComment(line string) string {
	inSingle := false
	inDouble := false
	for index, char := range line {
		switch char {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '#':
			if !inSingle && !inDouble {
				return line[:index]
			}
		}
	}
	return line
}

func unquoteSignerValue(value string) string {
	if len(value) >= 2 {
		if (value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'') {
			return value[1 : len(value)-1]
		}
	}
	return value
}
