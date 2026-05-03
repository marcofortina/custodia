package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"custodia/internal/config"
	"custodia/internal/httpapi"
	"custodia/internal/model"
	"custodia/internal/mtls"
	"custodia/internal/ratelimit"
	"custodia/internal/store"
)

func main() {
	cfg := config.Load()
	ctx := context.Background()

	vaultStore, closeStore, err := buildStore(ctx, cfg)
	if err != nil {
		log.Fatalf("store init failed: %v", err)
	}
	defer closeStore()

	limiter, err := buildLimiter(cfg)
	if err != nil {
		log.Fatalf("rate limiter init failed: %v", err)
	}
	storeBackend := resolvedStoreBackend(cfg)
	rateLimitBackend := resolvedRateLimitBackend(cfg)
	if err := validateAdminClientIDs(cfg.AdminClientIDs); err != nil {
		log.Fatalf("admin client configuration failed: %v", err)
	}

	handler := httpapi.New(httpapi.Options{
		Store:                            vaultStore,
		Limiter:                          limiter,
		AdminClientIDs:                   cfg.AdminClientIDs,
		MaxEnvelopesPerSecret:            cfg.MaxEnvelopesPerSecret,
		ClientRateLimit:                  cfg.ClientRateLimitPerSecond,
		GlobalRateLimit:                  cfg.GlobalRateLimitPerSecond,
		IPRateLimit:                      cfg.IPRateLimitPerSecond,
		StoreBackend:                     storeBackend,
		RateLimitBackend:                 rateLimitBackend,
		ClientCAFile:                     cfg.ClientCAFile,
		ClientCRLFile:                    cfg.ClientCRLFile,
		WebMFARequired:                   cfg.WebMFARequired,
		WebTOTPSecret:                    cfg.WebTOTPSecret,
		WebSessionSecret:                 cfg.WebSessionSecret,
		WebSessionTTL:                    time.Duration(cfg.WebSessionTTLSeconds) * time.Second,
		WebSessionSecure:                 !cfg.DevInsecureHTTP,
		WebPasskeyEnabled:                cfg.WebPasskeyEnabled,
		WebPasskeyRPID:                   cfg.WebPasskeyRPID,
		WebPasskeyRPName:                 cfg.WebPasskeyRPName,
		WebPasskeyChallengeTTL:           time.Duration(cfg.WebPasskeyChallengeTTLSeconds) * time.Second,
		WebPasskeyAssertionVerifyCommand: cfg.WebPasskeyAssertionVerifyCommand,
		DeploymentMode:                   cfg.DeploymentMode,
		DatabaseHATarget:                 cfg.DatabaseHATarget,
		AuditShipmentSink:                cfg.AuditShipmentSink,
	})

	server := &http.Server{
		Addr:              cfg.APIAddr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       time.Duration(cfg.HTTPReadTimeoutSeconds) * time.Second,
		WriteTimeout:      time.Duration(cfg.HTTPWriteTimeoutSeconds) * time.Second,
		IdleTimeout:       time.Duration(cfg.HTTPIdleTimeoutSeconds) * time.Second,
	}

	var healthServer *http.Server
	if cfg.HealthAddr != "" {
		healthServer = &http.Server{
			Addr:              cfg.HealthAddr,
			Handler:           buildHealthHandler(vaultStore, limiter),
			ReadHeaderTimeout: 2 * time.Second,
			ReadTimeout:       5 * time.Second,
			WriteTimeout:      5 * time.Second,
			IdleTimeout:       10 * time.Second,
		}
		go func() {
			log.Printf("starting health server on %s", cfg.HealthAddr)
			if err := healthServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Fatalf("health server failed: %v", err)
			}
		}()
	}

	go func() {
		if cfg.DevInsecureHTTP {
			log.Printf("starting insecure development HTTP server on %s", cfg.APIAddr)
			if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Fatalf("server failed: %v", err)
			}
			return
		}
		if cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" || cfg.ClientCAFile == "" {
			log.Fatalf("mTLS is required unless CUSTODIA_DEV_INSECURE_HTTP=true")
		}
		tlsConfig, err := mtls.ServerTLSConfigWithClientCRL(cfg.TLSCertFile, cfg.TLSKeyFile, cfg.ClientCAFile, cfg.ClientCRLFile)
		if err != nil {
			log.Fatalf("TLS config failed: %v", err)
		}
		server.TLSConfig = tlsConfig
		log.Printf("starting mTLS API server on %s", cfg.APIAddr)
		if err := server.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server failed: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.ShutdownTimeoutSeconds)*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("graceful shutdown failed: %v", err)
	}
	shutdownServer(shutdownCtx, healthServer)
}

func resolvedStoreBackend(cfg config.Config) string {
	backend := strings.ToLower(strings.TrimSpace(cfg.StoreBackend))
	if backend == "" {
		backend = "memory"
	}
	if cfg.DatabaseURL != "" && backend == "memory" {
		return "postgres"
	}
	return backend
}

func resolvedRateLimitBackend(cfg config.Config) string {
	backend := strings.ToLower(strings.TrimSpace(cfg.RateLimitBackend))
	if backend == "" {
		backend = "memory"
	}
	if cfg.ValkeyURL != "" && backend == "memory" {
		return "valkey"
	}
	return backend
}

func buildStore(ctx context.Context, cfg config.Config) (store.Store, func(), error) {
	switch resolvedStoreBackend(cfg) {
	case "postgres":
		postgresStore, err := store.NewPostgresStore(ctx, cfg.DatabaseURL)
		if err != nil {
			return nil, func() {}, err
		}
		if err := bootstrapClients(ctx, postgresStore, cfg.BootstrapClients); err != nil {
			postgresStore.Close()
			return nil, func() {}, err
		}
		return postgresStore, postgresStore.Close, nil
	case "memory":
		memoryStore := store.NewMemoryStore()
		if err := bootstrapClients(ctx, memoryStore, cfg.BootstrapClients); err != nil {
			return nil, func() {}, err
		}
		return memoryStore, func() {}, nil
	default:
		return nil, func() {}, errors.New("unsupported store backend")
	}
}

func validateAdminClientIDs(adminClientIDs map[string]bool) error {
	for clientID, enabled := range adminClientIDs {
		if enabled && !model.ValidClientID(clientID) {
			return errors.New("invalid admin client id")
		}
	}
	return nil
}

func bootstrapClients(ctx context.Context, vaultStore store.Store, clients map[string]string) error {
	for clientID, subject := range clients {
		if !model.ValidClientID(clientID) || !model.ValidMTLSSubject(subject) {
			return errors.New("invalid bootstrap client mapping")
		}
		err := vaultStore.CreateClient(ctx, model.Client{ClientID: clientID, MTLSSubject: subject})
		if err != nil && !errors.Is(err, store.ErrConflict) {
			return err
		}
	}
	return nil
}

func buildLimiter(cfg config.Config) (ratelimit.Limiter, error) {
	switch resolvedRateLimitBackend(cfg) {
	case "valkey":
		return ratelimit.NewValkeyLimiter(cfg.ValkeyURL)
	case "memory":
		return ratelimit.NewMemoryLimiter(), nil
	default:
		return nil, errors.New("unsupported rate limit backend")
	}
}
