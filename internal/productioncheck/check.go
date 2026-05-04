// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package productioncheck

import "strings"

const (
	SeverityCritical = "critical"
	SeverityWarning  = "warning"
)

type Finding struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

// CheckEnvironment is intentionally policy-only: it classifies configuration
// readiness but does not mutate env files or silently downgrade production goals.
func CheckEnvironment(env map[string]string) []Finding {
	findings := []Finding{}
	profile := strings.ToLower(envValue(env, "CUSTODIA_PROFILE"))
	if profile == "lite" {
		checkLiteEnvironment(env, &findings)
		return findings
	}
	checkFullEnvironment(env, &findings)
	return findings
}

// checkLiteEnvironment keeps Lite simple without weakening the security model:
// mTLS, MFA, audit integrity, and opaque crypto boundaries remain mandatory.
func checkLiteEnvironment(env map[string]string, findings *[]Finding) {
	add := func(code, severity, message string) { addFinding(findings, code, severity, message) }
	if truthy(envValue(env, "CUSTODIA_DEV_INSECURE_HTTP")) {
		add("api_insecure_http", SeverityCritical, "CUSTODIA_DEV_INSECURE_HTTP must be false for Lite deployments outside local development")
	}
	if strings.ToLower(envValue(env, "CUSTODIA_STORE_BACKEND")) != "sqlite" {
		add("store_backend", SeverityCritical, "CUSTODIA_STORE_BACKEND must be sqlite for the Lite profile")
	}
	if envValue(env, "CUSTODIA_DATABASE_URL") == "" {
		add("database_url", SeverityCritical, "CUSTODIA_DATABASE_URL is required for the Lite SQLite database file")
	}
	if backend := strings.ToLower(envValue(env, "CUSTODIA_RATE_LIMIT_BACKEND")); backend != "" && backend != "memory" {
		add("rate_limit_backend", SeverityWarning, "CUSTODIA_RATE_LIMIT_BACKEND should be memory for the Lite single-node profile")
	}
	for _, key := range []string{"CUSTODIA_TLS_CERT_FILE", "CUSTODIA_TLS_KEY_FILE", "CUSTODIA_CLIENT_CA_FILE", "CUSTODIA_CLIENT_CRL_FILE"} {
		if envValue(env, key) == "" {
			add(strings.ToLower(strings.TrimPrefix(key, "CUSTODIA_")), SeverityCritical, key+" is required for Lite mTLS")
		}
	}
	if envValue(env, "CUSTODIA_ADMIN_CLIENT_IDS") == "" {
		add("admin_client_ids", SeverityCritical, "CUSTODIA_ADMIN_CLIENT_IDS is required for Lite administration")
	}
	if !truthy(envValue(env, "CUSTODIA_WEB_MFA_REQUIRED")) {
		add("web_mfa_required", SeverityCritical, "CUSTODIA_WEB_MFA_REQUIRED must be true for Lite")
	}
	if envValue(env, "CUSTODIA_WEB_TOTP_SECRET") == "" {
		add("web_totp_secret", SeverityCritical, "CUSTODIA_WEB_TOTP_SECRET is required for Lite TOTP MFA")
	}
	if len(envValue(env, "CUSTODIA_WEB_SESSION_SECRET")) < 32 {
		add("web_session_secret", SeverityCritical, "CUSTODIA_WEB_SESSION_SECRET must be at least 32 bytes")
	}
	if truthy(envValue(env, "CUSTODIA_WEB_PASSKEY_ENABLED")) && envValue(env, "CUSTODIA_WEB_PASSKEY_ASSERTION_VERIFY_COMMAND") == "" {
		add("web_passkey_assertion_verify_command", SeverityWarning, "passkeys in Lite require an external assertion verifier command")
	}
	if provider := strings.ToLower(envValue(env, "CUSTODIA_SIGNER_KEY_PROVIDER")); provider != "" && provider != "file" {
		add("signer_key_provider", SeverityWarning, "CUSTODIA_SIGNER_KEY_PROVIDER should be file for the Lite default profile")
	}
	if envValue(env, "CUSTODIA_SIGNER_CA_CERT_FILE") == "" {
		add("signer_ca_cert_file", SeverityCritical, "CUSTODIA_SIGNER_CA_CERT_FILE is required for Lite local CA operations")
	}
	if envValue(env, "CUSTODIA_SIGNER_CA_KEY_FILE") == "" {
		add("signer_ca_key_file", SeverityCritical, "CUSTODIA_SIGNER_CA_KEY_FILE is required for Lite local CA operations")
	}
	if envValue(env, "CUSTODIA_SIGNER_CA_KEY_PASSPHRASE_FILE") == "" {
		add("signer_ca_key_passphrase_file", SeverityWarning, "CUSTODIA_SIGNER_CA_KEY_PASSPHRASE_FILE is recommended for Lite CA key protection")
	}
}

// checkFullEnvironment treats FULL production as evidence-driven. Warnings are
// reserved for topology quality; missing security boundaries are critical.
func checkFullEnvironment(env map[string]string, findings *[]Finding) {
	add := func(code, severity, message string) { addFinding(findings, code, severity, message) }
	if truthy(envValue(env, "CUSTODIA_DEV_INSECURE_HTTP")) {
		add("api_insecure_http", SeverityCritical, "CUSTODIA_DEV_INSECURE_HTTP must be false in production")
	}
	if strings.ToLower(envValue(env, "CUSTODIA_STORE_BACKEND")) != "postgres" {
		add("store_backend", SeverityCritical, "CUSTODIA_STORE_BACKEND must be postgres in production")
	}
	if envValue(env, "CUSTODIA_DATABASE_URL") == "" {
		add("database_url", SeverityCritical, "CUSTODIA_DATABASE_URL is required in production")
	}
	if strings.ToLower(envValue(env, "CUSTODIA_RATE_LIMIT_BACKEND")) != "valkey" {
		add("rate_limit_backend", SeverityCritical, "CUSTODIA_RATE_LIMIT_BACKEND must be valkey in production")
	}
	if envValue(env, "CUSTODIA_VALKEY_URL") == "" {
		add("valkey_url", SeverityCritical, "CUSTODIA_VALKEY_URL is required in production")
	}
	for _, key := range []string{"CUSTODIA_TLS_CERT_FILE", "CUSTODIA_TLS_KEY_FILE", "CUSTODIA_CLIENT_CA_FILE", "CUSTODIA_CLIENT_CRL_FILE"} {
		if envValue(env, key) == "" {
			add(strings.ToLower(strings.TrimPrefix(key, "CUSTODIA_")), SeverityCritical, key+" is required in production")
		}
	}
	if envValue(env, "CUSTODIA_ADMIN_CLIENT_IDS") == "" {
		add("admin_client_ids", SeverityCritical, "CUSTODIA_ADMIN_CLIENT_IDS is required in production")
	}
	if !truthy(envValue(env, "CUSTODIA_WEB_MFA_REQUIRED")) {
		add("web_mfa_required", SeverityCritical, "CUSTODIA_WEB_MFA_REQUIRED must be true in production")
	}
	if envValue(env, "CUSTODIA_WEB_TOTP_SECRET") == "" {
		add("web_totp_secret", SeverityCritical, "CUSTODIA_WEB_TOTP_SECRET is required while TOTP remains the enforced web MFA method")
	}
	if len(envValue(env, "CUSTODIA_WEB_SESSION_SECRET")) < 32 {
		add("web_session_secret", SeverityCritical, "CUSTODIA_WEB_SESSION_SECRET must be at least 32 bytes")
	}
	if truthy(envValue(env, "CUSTODIA_WEB_PASSKEY_ENABLED")) && envValue(env, "CUSTODIA_WEB_PASSKEY_ASSERTION_VERIFY_COMMAND") == "" {
		add("web_passkey_assertion_verify_command", SeverityCritical, "CUSTODIA_WEB_PASSKEY_ASSERTION_VERIFY_COMMAND is required when passkeys are enabled in production")
	}
	deploymentMode := strings.ToLower(envValue(env, "CUSTODIA_DEPLOYMENT_MODE"))
	if deploymentMode == "" || deploymentMode == "single-region" {
		add("deployment_mode", SeverityWarning, "CUSTODIA_DEPLOYMENT_MODE should describe the HA deployment topology")
	}
	haTarget := strings.ToLower(envValue(env, "CUSTODIA_DATABASE_HA_TARGET"))
	if haTarget == "" || haTarget == "external" {
		add("database_ha_target", SeverityWarning, "CUSTODIA_DATABASE_HA_TARGET should name the concrete HA database target")
	}
	if envValue(env, "CUSTODIA_AUDIT_SHIPMENT_SINK") == "" {
		add("audit_shipment_sink", SeverityCritical, "CUSTODIA_AUDIT_SHIPMENT_SINK is required for WORM/SIEM archival workflows")
	}
	if truthy(envValue(env, "CUSTODIA_SIGNER_DEV_INSECURE_HTTP")) {
		add("signer_insecure_http", SeverityCritical, "CUSTODIA_SIGNER_DEV_INSECURE_HTTP must be false in production")
	}
	if strings.ToLower(envValue(env, "CUSTODIA_SIGNER_KEY_PROVIDER")) != "pkcs11" {
		add("signer_key_provider", SeverityCritical, "CUSTODIA_SIGNER_KEY_PROVIDER must be pkcs11 for production HSM boundary enforcement")
	}
	if envValue(env, "CUSTODIA_SIGNER_PKCS11_SIGN_COMMAND") == "" {
		add("signer_pkcs11_sign_command", SeverityCritical, "CUSTODIA_SIGNER_PKCS11_SIGN_COMMAND is required when the pkcs11 signer provider is used")
	}
	for _, key := range []string{"CUSTODIA_SIGNER_TLS_CERT_FILE", "CUSTODIA_SIGNER_TLS_KEY_FILE", "CUSTODIA_SIGNER_CLIENT_CA_FILE", "CUSTODIA_SIGNER_ADMIN_SUBJECTS", "CUSTODIA_SIGNER_AUDIT_LOG_FILE", "CUSTODIA_SIGNER_CRL_FILE"} {
		if envValue(env, key) == "" {
			add(strings.ToLower(strings.TrimPrefix(key, "CUSTODIA_SIGNER_")), SeverityCritical, key+" is required in production")
		}
	}
}

func addFinding(findings *[]Finding, code, severity, message string) {
	*findings = append(*findings, Finding{Code: code, Severity: severity, Message: message})
}

func HasCritical(findings []Finding) bool {
	for _, finding := range findings {
		if finding.Severity == SeverityCritical {
			return true
		}
	}
	return false
}

func envValue(env map[string]string, key string) string {
	return strings.TrimSpace(env[key])
}

func truthy(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "t", "true", "yes", "y", "on":
		return true
	default:
		return false
	}
}
