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

	"custodia/internal/id"
	"custodia/internal/mtls"
	"custodia/internal/signing"
)

type signerConfig struct {
	addr            string
	tlsCertFile     string
	tlsKeyFile      string
	clientCAFile    string
	caCertFile      string
	caKeyFile       string
	adminSubjects   map[string]bool
	defaultTTLHours int
	devInsecureHTTP bool
	shutdownTimeout time.Duration
}

type signerServer struct {
	signer          *signing.ClientCertificateSigner
	adminSubjects   map[string]bool
	defaultTTLHours int
	devInsecureHTTP bool
}

func main() {
	cfg := loadConfig()
	caCertPEM, err := os.ReadFile(cfg.caCertFile)
	if err != nil {
		log.Fatalf("read CA certificate failed: %v", err)
	}
	caKeyPEM, err := os.ReadFile(cfg.caKeyFile)
	if err != nil {
		log.Fatalf("read CA key failed: %v", err)
	}
	clientSigner, err := signing.NewClientCertificateSigner(caCertPEM, caKeyPEM)
	if err != nil {
		log.Fatalf("signer init failed: %v", err)
	}
	if len(cfg.adminSubjects) == 0 {
		log.Fatalf("at least one CUSTODIA_SIGNER_ADMIN_SUBJECTS entry is required")
	}
	handler := newSignerServer(clientSigner, cfg.adminSubjects, cfg.defaultTTLHours, cfg.devInsecureHTTP)
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

func newSignerServer(clientSigner *signing.ClientCertificateSigner, adminSubjects map[string]bool, defaultTTLHours int, devInsecureHTTP bool) http.Handler {
	if defaultTTLHours <= 0 {
		defaultTTLHours = int(signing.DefaultClientCertificateTTL / time.Hour)
	}
	server := &signerServer{
		signer:          clientSigner,
		adminSubjects:   adminSubjects,
		defaultTTLHours: defaultTTLHours,
		devInsecureHTTP: devInsecureHTTP,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", server.handleHealth)
	mux.HandleFunc("GET /live", server.handleHealth)
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

func (s *signerServer) handleSignClientCertificate(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) {
		writeError(w, http.StatusForbidden, "admin_required")
		return
	}
	if !strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/json") {
		writeError(w, http.StatusUnsupportedMediaType, "unsupported_media_type")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1024*1024)
	var req signing.SignClientCertificateRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
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
		writeError(w, http.StatusBadRequest, "invalid_csr")
		return
	}
	writeJSON(w, http.StatusCreated, res)
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
		addr:            env("CUSTODIA_SIGNER_ADDR", ":9444"),
		tlsCertFile:     os.Getenv("CUSTODIA_SIGNER_TLS_CERT_FILE"),
		tlsKeyFile:      os.Getenv("CUSTODIA_SIGNER_TLS_KEY_FILE"),
		clientCAFile:    os.Getenv("CUSTODIA_SIGNER_CLIENT_CA_FILE"),
		caCertFile:      os.Getenv("CUSTODIA_SIGNER_CA_CERT_FILE"),
		caKeyFile:       os.Getenv("CUSTODIA_SIGNER_CA_KEY_FILE"),
		adminSubjects:   envSet("CUSTODIA_SIGNER_ADMIN_SUBJECTS"),
		defaultTTLHours: envInt("CUSTODIA_SIGNER_DEFAULT_TTL_HOURS", int(signing.DefaultClientCertificateTTL/time.Hour)),
		devInsecureHTTP: envBool("CUSTODIA_SIGNER_DEV_INSECURE_HTTP", false),
		shutdownTimeout: time.Duration(envInt("CUSTODIA_SIGNER_SHUTDOWN_TIMEOUT_SECONDS", 10)) * time.Second,
	}
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
