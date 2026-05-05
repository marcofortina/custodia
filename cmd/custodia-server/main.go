// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

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

// main wires the runtime boundary: opaque secret storage, mTLS identity,
// rate limiting, and web MFA all terminate in the HTTP API layer below.
func main() {
	cfg, err := config.LoadWithArgs(os.Args[1:])
	if err != nil {
		log.Fatalf("config load failed: %v", err)
	}
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

	if err := validateDedicatedWebListener(cfg.APIAddr, cfg.WebAddr); err != nil {
		log.Fatalf("invalid listener configuration: %v", err)
	}

	server := buildRuntimeServer(cfg.APIAddr, httpapi.APIOnly(handler), cfg)
	webServer := buildRuntimeServer(cfg.WebAddr, httpapi.WebOnly(handler), cfg)

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

	if cfg.DevInsecureHTTP {
		go serveRuntimeServer("insecure development API server", server, true)
		go serveRuntimeServer("insecure development web server", webServer, true)
	} else {
		if cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" || cfg.ClientCAFile == "" {
			log.Fatalf("mTLS is required unless CUSTODIA_DEV_INSECURE_HTTP=true")
		}
		tlsConfig, err := mtls.ServerTLSConfigWithClientCRL(cfg.TLSCertFile, cfg.TLSKeyFile, cfg.ClientCAFile, cfg.ClientCRLFile)
		if err != nil {
			log.Fatalf("TLS config failed: %v", err)
		}
		server.TLSConfig = tlsConfig.Clone()
		webServer.TLSConfig = tlsConfig.Clone()
		go serveRuntimeServer("mTLS API server", server, false)
		go serveRuntimeServer("mTLS web server", webServer, false)
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.ShutdownTimeoutSeconds)*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("graceful API shutdown failed: %v", err)
	}
	shutdownServer(shutdownCtx, webServer)
	shutdownServer(shutdownCtx, healthServer)
}

func buildRuntimeServer(addr string, handler http.Handler, cfg config.Config) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       time.Duration(cfg.HTTPReadTimeoutSeconds) * time.Second,
		WriteTimeout:      time.Duration(cfg.HTTPWriteTimeoutSeconds) * time.Second,
		IdleTimeout:       time.Duration(cfg.HTTPIdleTimeoutSeconds) * time.Second,
	}
}

func validateDedicatedWebListener(apiAddr, webAddr string) error {
	if strings.TrimSpace(apiAddr) == "" {
		return errors.New("api_addr is required")
	}
	if strings.TrimSpace(webAddr) == "" {
		return errors.New("web_addr is required")
	}
	if strings.TrimSpace(apiAddr) == strings.TrimSpace(webAddr) {
		return errors.New("web_addr must be different from api_addr")
	}
	return nil
}

func serveRuntimeServer(name string, server *http.Server, insecure bool) {
	if server == nil {
		return
	}
	log.Printf("starting %s on %s", name, server.Addr)
	var err error
	if insecure {
		err = server.ListenAndServe()
	} else {
		err = server.ListenAndServeTLS("", "")
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("%s failed: %v", name, err)
	}
}

// resolvedStoreBackend preserves the historical convenience where DATABASE_URL
// selects Postgres unless an explicit backend/profile has already made a choice.
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

// buildStore is the only place where deployment profile storage becomes runtime
// storage. Keeping it centralized prevents Lite/FULL drift in HTTP handlers.
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
	case "sqlite":
		sqliteStore, err := store.NewSQLiteStore(ctx, cfg.DatabaseURL)
		if err != nil {
			return nil, func() {}, err
		}
		if err := bootstrapClients(ctx, sqliteStore, cfg.BootstrapClients); err != nil {
			sqliteStore.Close()
			return nil, func() {}, err
		}
		return sqliteStore, sqliteStore.Close, nil
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

// bootstrapClients is idempotent by design so package examples and single-node
// Lite deployments can restart without recreating initial client identities.
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
