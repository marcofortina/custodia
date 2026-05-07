// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package config

import (
	"os"
	"strings"
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

func TestLoadReadsDefaultLogFile(t *testing.T) {
	cfg := Load()
	if cfg.LogFile != "/var/log/custodia/custodia.log" {
		t.Fatalf("expected default log file, got %q", cfg.LogFile)
	}
}

func TestLoadReadsLogFileOverride(t *testing.T) {
	t.Setenv("CUSTODIA_LOG_FILE", "/tmp/custodia.log")
	cfg := Load()
	if cfg.LogFile != "/tmp/custodia.log" {
		t.Fatalf("expected log file from env, got %q", cfg.LogFile)
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

func TestLoadDeployExampleServerConfigs(t *testing.T) {
	for _, tc := range []struct {
		name         string
		path         string
		profile      string
		storeBackend string
		rateBackend  string
	}{
		{name: "lite", path: "../../deploy/examples/custodia-server.lite.yaml", profile: ProfileLite, storeBackend: "sqlite", rateBackend: "memory"},
		{name: "full", path: "../../deploy/examples/custodia-server.full.yaml", profile: ProfileFull, storeBackend: "postgres", rateBackend: "valkey"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := LoadWithArgs([]string{"--config", tc.path})
			if err != nil {
				t.Fatalf("LoadWithArgs() error = %v", err)
			}
			if cfg.Profile != tc.profile || cfg.StoreBackend != tc.storeBackend || cfg.RateLimitBackend != tc.rateBackend {
				t.Fatalf("unexpected deploy example config: %+v", cfg)
			}
			if cfg.APIAddr == "" || cfg.WebAddr == "" || cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" || cfg.ClientCAFile == "" {
				t.Fatalf("expected listener and TLS fields from deploy example: %+v", cfg)
			}
			if tc.name == "lite" && (cfg.BootstrapClients["admin"] != "admin" || !cfg.AdminClientIDs["admin"]) {
				t.Fatalf("expected lite admin bootstrap identity: %+v", cfg)
			}
		})
	}
}

func TestDeployExampleServerConfigsAvoidLegacyFlatRuntimeKeys(t *testing.T) {
	flatTopLevelKeys := []string{
		"api_addr:",
		"web_addr:",
		"log_file:",
		"store_backend:",
		"database_url:",
		"rate_limit_backend:",
		"valkey_url:",
		"web_mfa_required:",
		"web_passkey_enabled:",
		"client_ca_file:",
		"client_crl_file:",
		"tls_cert_file:",
		"tls_key_file:",
		"deployment_mode:",
		"database_ha_target:",
		"audit_shipment_sink:",
		"signer_key_provider:",
		"signer_ca_cert_file:",
		"signer_ca_key_file:",
		"signer_ca_key_passphrase_file:",
		"signer_pkcs11_sign_command:",
	}
	for _, path := range []string{"../../deploy/examples/custodia-server.lite.yaml", "../../deploy/examples/custodia-server.full.yaml"} {
		t.Run(path, func(t *testing.T) {
			payload, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("ReadFile() error = %v", err)
			}
			for _, key := range flatTopLevelKeys {
				if hasTopLevelYAMLKey(string(payload), key) {
					t.Fatalf("deploy example %s still uses flat scalar key %q:\n%s", path, key, payload)
				}
			}
		})
	}
}

func hasTopLevelYAMLKey(payload, key string) bool {
	for _, line := range strings.Split(payload, "\n") {
		if strings.HasPrefix(line, key) {
			return true
		}
	}
	return false
}

func TestLoadYAMLConfigWithEnvOverride(t *testing.T) {
	path := t.TempDir() + "/custodia.yaml"
	writeConfigTestFile(t, path, `profile: lite
api_addr: ":9443"
log_file: /tmp/custodia.log
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
	if cfg.Profile != ProfileLite || cfg.APIAddr != ":9443" || cfg.LogFile != "/tmp/custodia.log" || cfg.DatabaseURL != "file:/tmp/lite.db" {
		t.Fatalf("unexpected yaml config: %+v", cfg)
	}
	if cfg.StoreBackend != "memory" || !cfg.WebPasskeyEnabled {
		t.Fatalf("expected env override after yaml, got %+v", cfg)
	}
	if !cfg.AdminClientIDs["admin"] || !cfg.AdminClientIDs["ops"] {
		t.Fatalf("expected admin client ids from yaml: %+v", cfg.AdminClientIDs)
	}
}

func TestLoadStructuredYAMLConfigSections(t *testing.T) {
	path := t.TempDir() + "/custodia.yaml"
	writeConfigTestFile(t, path, `profile: lite
server:
  api_addr: ":8444"
  web_addr: ":9444"
  log_file: /tmp/custodia.log
storage:
  backend: sqlite
  database_url: "file:/tmp/custodia.db"
rate_limit:
  backend: memory
  client_per_second: 11
  global_per_second: 22
  ip_per_second: 33
http:
  read_timeout_seconds: 10
  write_timeout_seconds: 20
  idle_timeout_seconds: 30
  shutdown_timeout_seconds: 40
tls:
  cert_file: /etc/custodia/server.crt
  key_file: /etc/custodia/server.key
  client_ca_file: /etc/custodia/client-ca.crt
  client_crl_file: /etc/custodia/client.crl.pem
web:
  mfa_required: true
  passkey_enabled: false
  session_ttl_seconds: 120
deployment:
  mode: lite-single-node
  database_ha_target: none
  audit_shipment_sink: s3://audit
signer:
  key_provider: file
  ca_cert_file: /etc/custodia/ca.crt
  ca_key_file: /etc/custodia/ca.key
  ca_key_passphrase_file: /etc/custodia/ca.pass
limits:
  max_envelopes_per_secret: 55
bootstrap_clients:
  - client_id: admin
    mtls_subject: admin
admin_client_ids:
  - admin
`)
	cfg, err := LoadWithArgs([]string{"--config", path})
	if err != nil {
		t.Fatalf("LoadWithArgs() error = %v", err)
	}
	if cfg.APIAddr != ":8444" || cfg.WebAddr != ":9444" || cfg.LogFile != "/tmp/custodia.log" {
		t.Fatalf("unexpected server section config: %+v", cfg)
	}
	if cfg.StoreBackend != "sqlite" || cfg.DatabaseURL != "file:/tmp/custodia.db" || cfg.RateLimitBackend != "memory" {
		t.Fatalf("unexpected storage/rate config: %+v", cfg)
	}
	if cfg.ClientRateLimitPerSecond != 11 || cfg.GlobalRateLimitPerSecond != 22 || cfg.IPRateLimitPerSecond != 33 {
		t.Fatalf("unexpected rate limits: %+v", cfg)
	}
	if cfg.HTTPReadTimeoutSeconds != 10 || cfg.HTTPWriteTimeoutSeconds != 20 || cfg.HTTPIdleTimeoutSeconds != 30 || cfg.ShutdownTimeoutSeconds != 40 {
		t.Fatalf("unexpected http timeouts: %+v", cfg)
	}
	if cfg.TLSCertFile != "/etc/custodia/server.crt" || cfg.TLSKeyFile != "/etc/custodia/server.key" || cfg.ClientCAFile != "/etc/custodia/client-ca.crt" || cfg.ClientCRLFile != "/etc/custodia/client.crl.pem" {
		t.Fatalf("unexpected tls config: %+v", cfg)
	}
	if !cfg.WebMFARequired || cfg.WebPasskeyEnabled || cfg.WebSessionTTLSeconds != 120 {
		t.Fatalf("unexpected web config: %+v", cfg)
	}
	if cfg.DeploymentMode != "lite-single-node" || cfg.DatabaseHATarget != "none" || cfg.AuditShipmentSink != "s3://audit" {
		t.Fatalf("unexpected deployment config: %+v", cfg)
	}
	if cfg.SignerKeyProvider != "file" || cfg.SignerCACertFile != "/etc/custodia/ca.crt" || cfg.SignerCAKeyFile != "/etc/custodia/ca.key" || cfg.SignerCAKeyPassphraseFile != "/etc/custodia/ca.pass" {
		t.Fatalf("unexpected signer config: %+v", cfg)
	}
	if cfg.MaxEnvelopesPerSecret != 55 || cfg.BootstrapClients["admin"] != "admin" || !cfg.AdminClientIDs["admin"] {
		t.Fatalf("unexpected limits/identity config: %+v", cfg)
	}
}

func TestLoadStructuredYAMLRejectsUnknownSectionKey(t *testing.T) {
	path := t.TempDir() + "/custodia.yaml"
	writeConfigTestFile(t, path, `profile: lite
storage:
  made_up: nope
`)
	if _, err := LoadWithArgs([]string{"--config", path}); err == nil {
		t.Fatal("expected unknown section key error")
	}
}

func TestLoadStructuredYAMLConfigWithIdentityLists(t *testing.T) {
	path := t.TempDir() + "/custodia.yaml"
	writeConfigTestFile(t, path, `profile: lite
api_addr: ":9443"
bootstrap_clients:
  - client_id: admin
    mtls_subject: admin
  - client_id: ops
    mtls_subject: ops-admin
admin_client_ids:
  - admin
  - ops
`)
	cfg, err := LoadWithArgs([]string{"--config", path})
	if err != nil {
		t.Fatalf("LoadWithArgs() error = %v", err)
	}
	if cfg.BootstrapClients["admin"] != "admin" || cfg.BootstrapClients["ops"] != "ops-admin" {
		t.Fatalf("unexpected bootstrap clients: %+v", cfg.BootstrapClients)
	}
	if !cfg.AdminClientIDs["admin"] || !cfg.AdminClientIDs["ops"] {
		t.Fatalf("unexpected admin ids: %+v", cfg.AdminClientIDs)
	}
}

func TestLoadStructuredYAMLRejectsIncompleteBootstrapClient(t *testing.T) {
	path := t.TempDir() + "/custodia.yaml"
	writeConfigTestFile(t, path, `profile: lite
bootstrap_clients:
  - client_id: admin
admin_client_ids:
  - admin
`)
	if _, err := LoadWithArgs([]string{"--config", path}); err == nil {
		t.Fatal("expected incomplete bootstrap client error")
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

func TestLoadFileIgnoresEnvironmentOverrides(t *testing.T) {
	t.Setenv("CUSTODIA_PROFILE", "full")
	t.Setenv("CUSTODIA_STORE_BACKEND", "postgres")
	path := t.TempDir() + "/custodia.yaml"
	writeConfigTestFile(t, path, `profile: lite
storage:
  backend: sqlite
  database_url: "file:/tmp/custodia.db"
`)
	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile() error = %v", err)
	}
	if cfg.Profile != ProfileLite || cfg.StoreBackend != "sqlite" {
		t.Fatalf("LoadFile applied environment overrides: %+v", cfg)
	}
}
