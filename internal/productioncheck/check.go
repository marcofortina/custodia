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

func CheckEnvironment(env map[string]string) []Finding {
	var findings []Finding
	add := func(code, severity, message string) {
		findings = append(findings, Finding{Code: code, Severity: severity, Message: message})
	}
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
	for _, key := range []string{"CUSTODIA_SIGNER_TLS_CERT_FILE", "CUSTODIA_SIGNER_TLS_KEY_FILE", "CUSTODIA_SIGNER_CLIENT_CA_FILE", "CUSTODIA_SIGNER_ADMIN_SUBJECTS", "CUSTODIA_SIGNER_AUDIT_LOG_FILE", "CUSTODIA_SIGNER_CRL_FILE"} {
		if envValue(env, key) == "" {
			add(strings.ToLower(strings.TrimPrefix(key, "CUSTODIA_SIGNER_")), SeverityCritical, key+" is required in production")
		}
	}
	return findings
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
