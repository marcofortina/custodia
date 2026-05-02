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

	handler := httpapi.New(httpapi.Options{
		Store:                 vaultStore,
		Limiter:               limiter,
		AdminClientIDs:        cfg.AdminClientIDs,
		MaxEnvelopesPerSecret: cfg.MaxEnvelopesPerSecret,
		ClientRateLimit:       cfg.ClientRateLimitPerSecond,
		GlobalRateLimit:       cfg.GlobalRateLimitPerSecond,
	})

	server := &http.Server{
		Addr:              cfg.APIAddr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
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
		tlsConfig, err := mtls.ServerTLSConfig(cfg.TLSCertFile, cfg.TLSKeyFile, cfg.ClientCAFile)
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
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("graceful shutdown failed: %v", err)
	}
}

func buildStore(ctx context.Context, cfg config.Config) (store.Store, func(), error) {
	if strings.EqualFold(cfg.StoreBackend, "postgres") || cfg.DatabaseURL != "" {
		postgresStore, err := store.NewPostgresStore(ctx, cfg.DatabaseURL)
		if err != nil {
			return nil, func() {}, err
		}
		return postgresStore, postgresStore.Close, nil
	}
	memoryStore := store.NewMemoryStore()
	for clientID, subject := range cfg.BootstrapClients {
		if err := memoryStore.CreateClient(ctx, model.Client{ClientID: clientID, MTLSSubject: subject}); err != nil {
			return nil, func() {}, err
		}
	}
	return memoryStore, func() {}, nil
}

func buildLimiter(cfg config.Config) (ratelimit.Limiter, error) {
	if strings.EqualFold(cfg.RateLimitBackend, "valkey") || cfg.ValkeyURL != "" {
		return ratelimit.NewValkeyLimiter(cfg.ValkeyURL)
	}
	return ratelimit.NewMemoryLimiter(), nil
}
