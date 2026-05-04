// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package liteupgrade

import (
	"strings"

	"custodia/internal/productioncheck"
)

func Check(liteEnv, fullEnv map[string]string) []productioncheck.Finding {
	findings := []productioncheck.Finding{}
	add := func(code, severity, message string) {
		findings = append(findings, productioncheck.Finding{Code: code, Severity: severity, Message: message})
	}
	checkLiteSource(liteEnv, add)
	checkFullTarget(fullEnv, add)
	return findings
}

func checkLiteSource(env map[string]string, add func(string, string, string)) {
	profile := strings.ToLower(envValue(env, "CUSTODIA_PROFILE"))
	if profile != "lite" && profile != "custom" {
		add("lite_source_profile", productioncheck.SeverityCritical, "source environment must use CUSTODIA_PROFILE=lite or custom")
	}
	if strings.ToLower(envValue(env, "CUSTODIA_STORE_BACKEND")) != "sqlite" {
		add("lite_source_store", productioncheck.SeverityCritical, "source environment must use CUSTODIA_STORE_BACKEND=sqlite")
	}
	if envValue(env, "CUSTODIA_DATABASE_URL") == "" {
		add("lite_source_database_url", productioncheck.SeverityCritical, "source environment must define CUSTODIA_DATABASE_URL for the SQLite database")
	}
	if strings.ToLower(envValue(env, "CUSTODIA_SIGNER_KEY_PROVIDER")) != "file" {
		add("lite_source_signer", productioncheck.SeverityWarning, "source Lite environment is expected to use the file signer provider before HSM migration")
	}
}

func checkFullTarget(env map[string]string, add func(string, string, string)) {
	profile := strings.ToLower(envValue(env, "CUSTODIA_PROFILE"))
	if profile != "full" && profile != "custom" {
		add("full_target_profile", productioncheck.SeverityCritical, "target environment must use CUSTODIA_PROFILE=full or custom")
	}
	if strings.ToLower(envValue(env, "CUSTODIA_STORE_BACKEND")) != "postgres" {
		add("full_target_store", productioncheck.SeverityCritical, "target environment must use CUSTODIA_STORE_BACKEND=postgres")
	}
	if envValue(env, "CUSTODIA_DATABASE_URL") == "" {
		add("full_target_database_url", productioncheck.SeverityCritical, "target environment must define CUSTODIA_DATABASE_URL for PostgreSQL or CockroachDB")
	}
	if strings.ToLower(envValue(env, "CUSTODIA_RATE_LIMIT_BACKEND")) != "valkey" {
		add("full_target_rate_limit", productioncheck.SeverityWarning, "target Full environment should use CUSTODIA_RATE_LIMIT_BACKEND=valkey")
	}
	if envValue(env, "CUSTODIA_VALKEY_URL") == "" {
		add("full_target_valkey_url", productioncheck.SeverityWarning, "target Full environment should define CUSTODIA_VALKEY_URL")
	}
	if strings.ToLower(envValue(env, "CUSTODIA_SIGNER_KEY_PROVIDER")) != "pkcs11" {
		add("full_target_signer", productioncheck.SeverityWarning, "target Full environment should use CUSTODIA_SIGNER_KEY_PROVIDER=pkcs11")
	}
	if envValue(env, "CUSTODIA_AUDIT_SHIPMENT_SINK") == "" {
		add("full_target_audit_shipment", productioncheck.SeverityWarning, "target Full environment should configure CUSTODIA_AUDIT_SHIPMENT_SINK")
	}
	if envValue(env, "CUSTODIA_DATABASE_HA_TARGET") == "" || strings.EqualFold(envValue(env, "CUSTODIA_DATABASE_HA_TARGET"), "none") {
		add("full_target_database_ha", productioncheck.SeverityWarning, "target Full environment should name the HA database target")
	}
}

func envValue(env map[string]string, key string) string {
	return strings.TrimSpace(env[key])
}
