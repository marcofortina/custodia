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
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"custodia/internal/build"
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
	if handled, code := handleInfoCommand(os.Args[1:], os.Stdout); handled {
		os.Exit(code)
	}
	if handled, code := handleConfigCommand(os.Args[1:], os.Stdout, os.Stderr); handled {
		os.Exit(code)
	}
	cfg, err := config.LoadWithArgs(os.Args[1:])
	if err != nil {
		log.Fatalf("config load failed: %v", err)
	}
	closeLog, err := configureLogging(cfg.LogFile)
	if err != nil {
		log.Fatalf("log file setup failed: %v", err)
	}
	defer closeLog()

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

const serverUsage = `Usage:
  custodia-server [configuration flags]
  custodia-server config validate --config FILE
  custodia-server config render --profile lite|full
  custodia-server version
  custodia-server --version
  custodia-server help

Runs the Custodia vault API and web console. Runtime configuration is loaded
from environment variables, config files, and supported config flags.
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
		fmt.Fprint(stdout, serverUsage)
		return true, 0
	default:
		return false, 0
	}
}

func handleConfigCommand(args []string, stdout, stderr io.Writer) (bool, int) {
	if len(args) == 0 || strings.TrimSpace(args[0]) != "config" {
		return false, 0
	}
	if len(args) < 2 {
		fmt.Fprintln(stderr, "missing config subcommand")
		return true, 2
	}
	switch strings.TrimSpace(args[1]) {
	case "validate":
		path, err := parseConfigValidatePath(args[2:])
		if err != nil {
			fmt.Fprintln(stderr, err)
			return true, 2
		}
		cfg, err := config.LoadFile(path)
		if err != nil {
			fmt.Fprintf(stderr, "config validate failed: %v\n", err)
			return true, 1
		}
		if err := validateConfigForOfflineCheck(cfg); err != nil {
			fmt.Fprintf(stderr, "config validate failed: %v\n", err)
			return true, 1
		}
		fmt.Fprintf(stdout, "configuration ok: %s\n", path)
		return true, 0
	case "render":
		profile, err := parseConfigRenderProfile(args[2:])
		if err != nil {
			fmt.Fprintln(stderr, err)
			return true, 2
		}
		content, err := renderServerConfigTemplate(profile)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return true, 2
		}
		fmt.Fprint(stdout, content)
		return true, 0
	default:
		fmt.Fprintf(stderr, "unknown config subcommand: %s\n", args[1])
		return true, 2
	}
}

func parseConfigRenderProfile(args []string) (string, error) {
	if len(args) == 0 {
		return "", errors.New("--profile is required")
	}
	arg := strings.TrimSpace(args[0])
	switch {
	case arg == "--profile":
		if len(args) < 2 || strings.TrimSpace(args[1]) == "" {
			return "", errors.New("--profile requires lite or full")
		}
		return strings.TrimSpace(args[1]), nil
	case strings.HasPrefix(arg, "--profile="):
		value := strings.TrimSpace(strings.TrimPrefix(arg, "--profile="))
		if value == "" {
			return "", errors.New("--profile requires lite or full")
		}
		return value, nil
	default:
		return "", fmt.Errorf("unknown config render argument: %s", arg)
	}
}

func renderServerConfigTemplate(profile string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(profile)) {
	case "lite":
		return serverLiteConfigTemplate, nil
	case "full":
		return serverFullConfigTemplate, nil
	default:
		return "", fmt.Errorf("unsupported profile: %s", profile)
	}
}

const serverLiteConfigTemplate = `profile: lite

server:
  api_addr: ":8443"
  web_addr: ":9443"
  log_file: /var/log/custodia/custodia.log

storage:
  backend: sqlite
  database_url: "file:/var/lib/custodia/custodia.db"

rate_limit:
  backend: memory

web:
  mfa_required: true
  passkey_enabled: false

tls:
  client_ca_file: /etc/custodia/client-ca.crt
  client_crl_file: /etc/custodia/client.crl.pem
  cert_file: /etc/custodia/server.crt
  key_file: /etc/custodia/server.key

deployment:
  mode: lite-single-node
  database_ha_target: none

signer:
  key_provider: file
  ca_cert_file: /etc/custodia/ca.crt
  ca_key_file: /etc/custodia/ca.key
  ca_key_passphrase_file: /etc/custodia/ca.pass

bootstrap_clients:
  - client_id: admin
    mtls_subject: admin

admin_client_ids:
  - admin
`

const serverFullConfigTemplate = `profile: full

server:
  api_addr: ":8443"
  web_addr: ":9443"
  log_file: /var/log/custodia/custodia.log

storage:
  backend: postgres
  database_url: "postgres://custodia:custodia@postgres.example.internal:5432/custodia?sslmode=require"

rate_limit:
  backend: valkey
  valkey_url: "redis://valkey.example.internal:6379/0"

web:
  mfa_required: true
  passkey_enabled: false

tls:
  client_ca_file: /etc/custodia/client-ca.crt
  client_crl_file: /etc/custodia/client.crl.pem
  cert_file: /etc/custodia/server.crt
  key_file: /etc/custodia/server.key

deployment:
  mode: production
  database_ha_target: external

audit:
  shipment_sink: none

signer:
  key_provider: file
  ca_cert_file: /etc/custodia/ca.crt
  ca_key_file: /etc/custodia/ca.key
  ca_key_passphrase_file: /etc/custodia/ca.pass

bootstrap_clients:
  - client_id: admin
    mtls_subject: admin

admin_client_ids:
  - admin
`

func parseConfigValidatePath(args []string) (string, error) {
	if len(args) == 0 {
		return "", errors.New("--config is required")
	}
	arg := strings.TrimSpace(args[0])
	switch {
	case arg == "--config":
		if len(args) < 2 || strings.TrimSpace(args[1]) == "" {
			return "", errors.New("--config requires a path")
		}
		return strings.TrimSpace(args[1]), nil
	case strings.HasPrefix(arg, "--config="):
		value := strings.TrimSpace(strings.TrimPrefix(arg, "--config="))
		if value == "" {
			return "", errors.New("--config requires a path")
		}
		return value, nil
	default:
		return "", fmt.Errorf("unknown config validate argument: %s", arg)
	}
}

func validateConfigForOfflineCheck(cfg config.Config) error {
	if cfg.StoreBackend != "memory" && cfg.StoreBackend != "sqlite" && cfg.StoreBackend != "postgres" {
		return fmt.Errorf("unsupported store backend: %s", cfg.StoreBackend)
	}
	if cfg.RateLimitBackend != "memory" && cfg.RateLimitBackend != "valkey" {
		return fmt.Errorf("unsupported rate limit backend: %s", cfg.RateLimitBackend)
	}
	if cfg.APIAddr == "" || cfg.WebAddr == "" {
		return errors.New("api and web listener addresses are required")
	}
	if err := validateDedicatedWebListener(cfg.APIAddr, cfg.WebAddr); err != nil {
		return err
	}
	if cfg.StoreBackend == "sqlite" || cfg.StoreBackend == "postgres" {
		if strings.TrimSpace(cfg.DatabaseURL) == "" {
			return fmt.Errorf("database_url is required for %s store backend", cfg.StoreBackend)
		}
	}
	if !cfg.DevInsecureHTTP && (cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" || cfg.ClientCAFile == "") {
		return errors.New("tls cert, tls key and client CA files are required unless dev insecure HTTP is enabled")
	}
	if err := validateAdminClientIDs(cfg.AdminClientIDs); err != nil {
		return err
	}
	return nil
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

func configureLogging(path string) (func(), error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return func() {}, nil
	}
	file, err := os.OpenFile(trimmed, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return nil, err
	}
	if err := file.Chmod(0o640); err != nil {
		if closeErr := file.Close(); closeErr != nil {
			return nil, errors.Join(err, closeErr)
		}
		return nil, err
	}
	previousOutput := log.Writer()
	log.SetOutput(io.MultiWriter(os.Stderr, file))
	return func() {
		log.SetOutput(previousOutput)
		if err := file.Close(); err != nil {
			log.Printf("log file close failed: %v", err)
		}
	}, nil
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
