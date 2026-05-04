// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package productioncheck

import "testing"

func TestCheckEnvironmentAcceptsHardenedProductionConfig(t *testing.T) {
	findings := CheckEnvironment(map[string]string{
		"CUSTODIA_STORE_BACKEND":                        "postgres",
		"CUSTODIA_DATABASE_URL":                         "postgres://db",
		"CUSTODIA_RATE_LIMIT_BACKEND":                   "valkey",
		"CUSTODIA_VALKEY_URL":                           "rediss://cache",
		"CUSTODIA_TLS_CERT_FILE":                        "/certs/api.crt",
		"CUSTODIA_TLS_KEY_FILE":                         "/certs/api.key",
		"CUSTODIA_CLIENT_CA_FILE":                       "/certs/ca.crt",
		"CUSTODIA_CLIENT_CRL_FILE":                      "/certs/client.crl",
		"CUSTODIA_ADMIN_CLIENT_IDS":                     "admin",
		"CUSTODIA_WEB_MFA_REQUIRED":                     "true",
		"CUSTODIA_WEB_TOTP_SECRET":                      "JBSWY3DPEHPK3PXP",
		"CUSTODIA_WEB_SESSION_SECRET":                   "0123456789abcdef0123456789abcdef",
		"CUSTODIA_WEB_PASSKEY_ENABLED":                  "true",
		"CUSTODIA_WEB_PASSKEY_ASSERTION_VERIFY_COMMAND": "/usr/local/bin/verify-passkey",
		"CUSTODIA_DEPLOYMENT_MODE":                      "multi-region",
		"CUSTODIA_DATABASE_HA_TARGET":                   "cockroachdb-multi-region",
		"CUSTODIA_AUDIT_SHIPMENT_SINK":                  "s3://custodia-audit",
		"CUSTODIA_SIGNER_KEY_PROVIDER":                  "pkcs11",
		"CUSTODIA_SIGNER_PKCS11_SIGN_COMMAND":           "/usr/local/bin/custodia-pkcs11-sign",
		"CUSTODIA_SIGNER_TLS_CERT_FILE":                 "/certs/signer.crt",
		"CUSTODIA_SIGNER_TLS_KEY_FILE":                  "/certs/signer.key",
		"CUSTODIA_SIGNER_CLIENT_CA_FILE":                "/certs/admin-ca.crt",
		"CUSTODIA_SIGNER_ADMIN_SUBJECTS":                "signer_admin",
		"CUSTODIA_SIGNER_AUDIT_LOG_FILE":                "/audit/signer.jsonl",
		"CUSTODIA_SIGNER_CRL_FILE":                      "/certs/client.crl",
	})
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %#v", findings)
	}
}

func TestCheckEnvironmentRejectsUnsafeDefaults(t *testing.T) {
	findings := CheckEnvironment(map[string]string{
		"CUSTODIA_DEV_INSECURE_HTTP":        "true",
		"CUSTODIA_STORE_BACKEND":            "memory",
		"CUSTODIA_RATE_LIMIT_BACKEND":       "memory",
		"CUSTODIA_WEB_SESSION_SECRET":       "short",
		"CUSTODIA_SIGNER_DEV_INSECURE_HTTP": "true",
		"CUSTODIA_SIGNER_KEY_PROVIDER":      "file",
	})
	if !HasCritical(findings) {
		t.Fatalf("expected critical findings, got %#v", findings)
	}
	assertFinding(t, findings, "api_insecure_http")
	assertFinding(t, findings, "store_backend")
	assertFinding(t, findings, "signer_key_provider")
	assertFinding(t, findings, "signer_pkcs11_sign_command")
}

func assertFinding(t *testing.T, findings []Finding, code string) {
	t.Helper()
	for _, finding := range findings {
		if finding.Code == code {
			return
		}
	}
	t.Fatalf("missing finding %q in %#v", code, findings)
}

func TestCheckEnvironmentRequiresPasskeyAssertionVerifierWhenPasskeysAreEnabled(t *testing.T) {
	findings := CheckEnvironment(map[string]string{
		"CUSTODIA_STORE_BACKEND":              "postgres",
		"CUSTODIA_DATABASE_URL":               "postgres://db",
		"CUSTODIA_RATE_LIMIT_BACKEND":         "valkey",
		"CUSTODIA_VALKEY_URL":                 "rediss://cache",
		"CUSTODIA_TLS_CERT_FILE":              "/certs/api.crt",
		"CUSTODIA_TLS_KEY_FILE":               "/certs/api.key",
		"CUSTODIA_CLIENT_CA_FILE":             "/certs/ca.crt",
		"CUSTODIA_CLIENT_CRL_FILE":            "/certs/client.crl",
		"CUSTODIA_ADMIN_CLIENT_IDS":           "admin",
		"CUSTODIA_WEB_MFA_REQUIRED":           "true",
		"CUSTODIA_WEB_TOTP_SECRET":            "JBSWY3DPEHPK3PXP",
		"CUSTODIA_WEB_SESSION_SECRET":         "0123456789abcdef0123456789abcdef",
		"CUSTODIA_WEB_PASSKEY_ENABLED":        "true",
		"CUSTODIA_DEPLOYMENT_MODE":            "multi-region",
		"CUSTODIA_DATABASE_HA_TARGET":         "cockroachdb-multi-region",
		"CUSTODIA_AUDIT_SHIPMENT_SINK":        "s3://custodia-audit",
		"CUSTODIA_SIGNER_KEY_PROVIDER":        "pkcs11",
		"CUSTODIA_SIGNER_PKCS11_SIGN_COMMAND": "/usr/local/bin/custodia-pkcs11-sign",
		"CUSTODIA_SIGNER_TLS_CERT_FILE":       "/certs/signer.crt",
		"CUSTODIA_SIGNER_TLS_KEY_FILE":        "/certs/signer.key",
		"CUSTODIA_SIGNER_CLIENT_CA_FILE":      "/certs/admin-ca.crt",
		"CUSTODIA_SIGNER_ADMIN_SUBJECTS":      "signer_admin",
		"CUSTODIA_SIGNER_AUDIT_LOG_FILE":      "/audit/signer.jsonl",
		"CUSTODIA_SIGNER_CRL_FILE":            "/certs/client.crl",
	})
	assertFinding(t, findings, "web_passkey_assertion_verify_command")
}

func TestCheckEnvironmentAcceptsLiteProfileConfig(t *testing.T) {
	findings := CheckEnvironment(map[string]string{
		"CUSTODIA_PROFILE":                       "lite",
		"CUSTODIA_STORE_BACKEND":                 "sqlite",
		"CUSTODIA_DATABASE_URL":                  "file:/var/lib/custodia/custodia.db",
		"CUSTODIA_RATE_LIMIT_BACKEND":            "memory",
		"CUSTODIA_TLS_CERT_FILE":                 "/etc/custodia/server.crt",
		"CUSTODIA_TLS_KEY_FILE":                  "/etc/custodia/server.key",
		"CUSTODIA_CLIENT_CA_FILE":                "/etc/custodia/client-ca.crt",
		"CUSTODIA_CLIENT_CRL_FILE":               "/etc/custodia/client.crl.pem",
		"CUSTODIA_ADMIN_CLIENT_IDS":              "admin",
		"CUSTODIA_WEB_MFA_REQUIRED":              "true",
		"CUSTODIA_WEB_TOTP_SECRET":               "JBSWY3DPEHPK3PXP",
		"CUSTODIA_WEB_SESSION_SECRET":            "0123456789abcdef0123456789abcdef",
		"CUSTODIA_SIGNER_KEY_PROVIDER":           "file",
		"CUSTODIA_SIGNER_CA_CERT_FILE":           "/etc/custodia/ca.crt",
		"CUSTODIA_SIGNER_CA_KEY_FILE":            "/etc/custodia/ca.key",
		"CUSTODIA_SIGNER_CA_KEY_PASSPHRASE_FILE": "/etc/custodia/ca.pass",
	})
	if HasCritical(findings) {
		t.Fatalf("expected no critical lite findings, got %#v", findings)
	}
}

func TestCheckEnvironmentWarnsForLiteMissingCAPassphrase(t *testing.T) {
	findings := CheckEnvironment(map[string]string{
		"CUSTODIA_PROFILE":             "lite",
		"CUSTODIA_STORE_BACKEND":       "sqlite",
		"CUSTODIA_DATABASE_URL":        "file:/var/lib/custodia/custodia.db",
		"CUSTODIA_RATE_LIMIT_BACKEND":  "memory",
		"CUSTODIA_TLS_CERT_FILE":       "/etc/custodia/server.crt",
		"CUSTODIA_TLS_KEY_FILE":        "/etc/custodia/server.key",
		"CUSTODIA_CLIENT_CA_FILE":      "/etc/custodia/client-ca.crt",
		"CUSTODIA_CLIENT_CRL_FILE":     "/etc/custodia/client.crl.pem",
		"CUSTODIA_ADMIN_CLIENT_IDS":    "admin",
		"CUSTODIA_WEB_MFA_REQUIRED":    "true",
		"CUSTODIA_WEB_TOTP_SECRET":     "JBSWY3DPEHPK3PXP",
		"CUSTODIA_WEB_SESSION_SECRET":  "0123456789abcdef0123456789abcdef",
		"CUSTODIA_SIGNER_KEY_PROVIDER": "file",
		"CUSTODIA_SIGNER_CA_CERT_FILE": "/etc/custodia/ca.crt",
		"CUSTODIA_SIGNER_CA_KEY_FILE":  "/etc/custodia/ca.key",
	})
	if HasCritical(findings) {
		t.Fatalf("expected only lite warning findings, got %#v", findings)
	}
	assertFinding(t, findings, "signer_ca_key_passphrase_file")
}
