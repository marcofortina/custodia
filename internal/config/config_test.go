// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package config

import (
	"os"
	"testing"
)

func TestLoadHTTPTimeoutsFromEnvironment(t *testing.T) {
	t.Setenv("CUSTODIA_HTTP_READ_TIMEOUT_SECONDS", "21")
	t.Setenv("CUSTODIA_HTTP_WRITE_TIMEOUT_SECONDS", "22")
	t.Setenv("CUSTODIA_HTTP_IDLE_TIMEOUT_SECONDS", "23")
	t.Setenv("CUSTODIA_SHUTDOWN_TIMEOUT_SECONDS", "24")

	cfg := Load()
	if cfg.HTTPReadTimeoutSeconds != 21 || cfg.HTTPWriteTimeoutSeconds != 22 || cfg.HTTPIdleTimeoutSeconds != 23 || cfg.ShutdownTimeoutSeconds != 24 {
		t.Fatalf("unexpected timeout config: %+v", cfg)
	}
}

func TestLoadHTTPTimeoutsKeepSafeDefaultsForInvalidValues(t *testing.T) {
	t.Setenv("CUSTODIA_HTTP_READ_TIMEOUT_SECONDS", "0")
	t.Setenv("CUSTODIA_HTTP_WRITE_TIMEOUT_SECONDS", "invalid")
	t.Setenv("CUSTODIA_HTTP_IDLE_TIMEOUT_SECONDS", "-1")
	t.Setenv("CUSTODIA_SHUTDOWN_TIMEOUT_SECONDS", "")

	cfg := Load()
	if cfg.HTTPReadTimeoutSeconds != 15 || cfg.HTTPWriteTimeoutSeconds != 15 || cfg.HTTPIdleTimeoutSeconds != 60 || cfg.ShutdownTimeoutSeconds != 10 {
		t.Fatalf("unexpected default timeout config: %+v", cfg)
	}
}

func TestLoadReadsOptionalHealthAddress(t *testing.T) {
	t.Setenv("CUSTODIA_HEALTH_ADDR", ":8080")
	cfg := Load()
	if cfg.HealthAddr != ":8080" {
		t.Fatalf("expected health addr from env, got %q", cfg.HealthAddr)
	}
}

func TestLoadWebAuthConfigFromEnvironment(t *testing.T) {
	t.Setenv("CUSTODIA_WEB_MFA_REQUIRED", "true")
	t.Setenv("CUSTODIA_WEB_TOTP_SECRET", "SECRET")
	t.Setenv("CUSTODIA_WEB_SESSION_SECRET", "01234567890123456789012345678901")
	t.Setenv("CUSTODIA_WEB_SESSION_TTL_SECONDS", "120")
	t.Setenv("CUSTODIA_WEB_PASSKEY_ENABLED", "true")
	t.Setenv("CUSTODIA_WEB_PASSKEY_RP_ID", "vault.example.com")
	t.Setenv("CUSTODIA_WEB_PASSKEY_RP_NAME", "Custodia Vault")
	t.Setenv("CUSTODIA_WEB_PASSKEY_CHALLENGE_TTL_SECONDS", "180")
	t.Setenv("CUSTODIA_WEB_PASSKEY_ASSERTION_VERIFY_COMMAND", "/usr/local/bin/verify-passkey")

	cfg := Load()
	if !cfg.WebMFARequired || cfg.WebTOTPSecret != "SECRET" || cfg.WebSessionSecret == "" || cfg.WebSessionTTLSeconds != 120 {
		t.Fatalf("unexpected web MFA config: %+v", cfg)
	}
	if !cfg.WebPasskeyEnabled || cfg.WebPasskeyRPID != "vault.example.com" || cfg.WebPasskeyRPName != "Custodia Vault" || cfg.WebPasskeyChallengeTTLSeconds != 180 || cfg.WebPasskeyAssertionVerifyCommand != "/usr/local/bin/verify-passkey" {
		t.Fatalf("unexpected passkey config: %+v", cfg)
	}
}

func TestLoadReadsDeploymentMetadata(t *testing.T) {
	t.Setenv("CUSTODIA_DEPLOYMENT_MODE", "multi-region")
	t.Setenv("CUSTODIA_DATABASE_HA_TARGET", "cockroachdb")
	t.Setenv("CUSTODIA_AUDIT_SHIPMENT_SINK", "s3://audit-bucket/custodia")
	cfg := Load()
	if cfg.DeploymentMode != "multi-region" || cfg.DatabaseHATarget != "cockroachdb" || cfg.AuditShipmentSink != "s3://audit-bucket/custodia" {
		t.Fatalf("unexpected deployment metadata: %+v", cfg)
	}
}

func TestLoadLiteProfileDefaults(t *testing.T) {
	t.Setenv("CUSTODIA_PROFILE", "lite")
	cfg := Load()
	if cfg.Profile != ProfileLite || cfg.StoreBackend != "sqlite" || cfg.DatabaseURL != "file:/var/lib/custodia/custodia.db" {
		t.Fatalf("unexpected lite store config: %+v", cfg)
	}
	if cfg.RateLimitBackend != "memory" || cfg.DeploymentMode != "lite-single-node" || cfg.DatabaseHATarget != "none" || !cfg.WebMFARequired || cfg.WebPasskeyEnabled {
		t.Fatalf("unexpected lite defaults: %+v", cfg)
	}
}

func TestLoadFullProfileDefaults(t *testing.T) {
	t.Setenv("CUSTODIA_PROFILE", "full")
	cfg := Load()
	if cfg.Profile != ProfileFull || cfg.StoreBackend != "postgres" || cfg.RateLimitBackend != "valkey" || cfg.DeploymentMode != "production" || !cfg.WebMFARequired {
		t.Fatalf("unexpected full defaults: %+v", cfg)
	}
}

func TestLoadYAMLConfigWithEnvOverride(t *testing.T) {
	path := t.TempDir() + "/custodia.yaml"
	writeConfigTestFile(t, path, `profile: lite
api_addr: ":9443"
store_backend: sqlite
database_url: file:/tmp/lite.db
web_mfa_required: true
web_passkey_enabled: false
admin_client_ids: admin,ops
`)
	t.Setenv("CUSTODIA_STORE_BACKEND", "memory")
	t.Setenv("CUSTODIA_WEB_PASSKEY_ENABLED", "true")
	cfg, err := LoadWithArgs([]string{"--config", path})
	if err != nil {
		t.Fatalf("LoadWithArgs() error = %v", err)
	}
	if cfg.Profile != ProfileLite || cfg.APIAddr != ":9443" || cfg.DatabaseURL != "file:/tmp/lite.db" {
		t.Fatalf("unexpected yaml config: %+v", cfg)
	}
	if cfg.StoreBackend != "memory" || !cfg.WebPasskeyEnabled {
		t.Fatalf("expected env override after yaml, got %+v", cfg)
	}
	if !cfg.AdminClientIDs["admin"] || !cfg.AdminClientIDs["ops"] {
		t.Fatalf("expected admin client ids from yaml: %+v", cfg.AdminClientIDs)
	}
}

func TestLoadWithArgsRejectsUnsupportedYAML(t *testing.T) {
	path := t.TempDir() + "/custodia.yaml"
	writeConfigTestFile(t, path, "profile:\n  name: lite\n")
	if _, err := LoadWithArgs([]string{"--config", path}); err == nil {
		t.Fatal("expected unsupported nested yaml error")
	}
}

func writeConfigTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
}

func TestLoadYAMLReadsSharedSignerSettings(t *testing.T) {
	path := t.TempDir() + "/custodia.yaml"
	writeConfigTestFile(t, path, `profile: lite
signer_key_provider: file
signer_ca_cert_file: /etc/custodia/ca.crt
signer_ca_key_file: /etc/custodia/ca.key
signer_ca_key_passphrase_file: /etc/custodia/ca.pass
signer_pkcs11_sign_command: /usr/local/bin/custodia-pkcs11-sign
`)
	cfg, err := LoadWithArgs([]string{"--config", path})
	if err != nil {
		t.Fatalf("LoadWithArgs() error = %v", err)
	}
	if cfg.SignerKeyProvider != "file" || cfg.SignerCACertFile != "/etc/custodia/ca.crt" || cfg.SignerCAKeyFile != "/etc/custodia/ca.key" || cfg.SignerCAKeyPassphraseFile != "/etc/custodia/ca.pass" || cfg.SignerPKCS11SignCommand != "/usr/local/bin/custodia-pkcs11-sign" {
		t.Fatalf("unexpected signer settings: %+v", cfg)
	}
}

func TestLoadSignerSettingsCanBeOverriddenByEnvironment(t *testing.T) {
	path := t.TempDir() + "/custodia.yaml"
	writeConfigTestFile(t, path, `profile: lite
signer_key_provider: file
signer_ca_cert_file: /etc/custodia/ca.crt
`)
	t.Setenv("CUSTODIA_SIGNER_KEY_PROVIDER", "pkcs11")
	t.Setenv("CUSTODIA_SIGNER_CA_CERT_FILE", "/env/ca.crt")
	cfg, err := LoadWithArgs([]string{"--config", path})
	if err != nil {
		t.Fatalf("LoadWithArgs() error = %v", err)
	}
	if cfg.SignerKeyProvider != "pkcs11" || cfg.SignerCACertFile != "/env/ca.crt" {
		t.Fatalf("unexpected env override signer settings: %+v", cfg)
	}
}
