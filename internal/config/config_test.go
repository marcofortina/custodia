package config

import "testing"

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
