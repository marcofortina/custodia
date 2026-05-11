// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	ProfileLite   = "lite"
	ProfileFull   = "full"
	ProfileCustom = "custom"
)

// Config is the single resolved runtime configuration shared by server, signer and CLI paths.
// New knobs should flow through this type first so env, YAML and profile defaults stay consistent.
type Config struct {
	Profile                          string
	ConfigFile                       string
	APIAddr                          string
	ServerURL                        string
	HealthAddr                       string
	WebAddr                          string
	LogFile                          string
	StoreBackend                     string
	DatabaseURL                      string
	TLSCertFile                      string
	TLSKeyFile                       string
	ClientCAFile                     string
	ClientCRLFile                    string
	DevInsecureHTTP                  bool
	BootstrapClients                 map[string]string
	AdminClientIDs                   map[string]bool
	MaxEnvelopesPerSecret            int
	RateLimitBackend                 string
	ValkeyURL                        string
	ClientRateLimitPerSecond         int
	GlobalRateLimitPerSecond         int
	IPRateLimitPerSecond             int
	HTTPReadTimeoutSeconds           int
	HTTPWriteTimeoutSeconds          int
	HTTPIdleTimeoutSeconds           int
	ShutdownTimeoutSeconds           int
	WebMFARequired                   bool
	WebTOTPSecret                    string
	WebSessionSecret                 string
	WebSessionTTLSeconds             int
	WebPasskeyEnabled                bool
	WebPasskeyRPID                   string
	WebPasskeyRPName                 string
	WebPasskeyChallengeTTLSeconds    int
	WebPasskeyAssertionVerifyCommand string
	DeploymentMode                   string
	DatabaseHATarget                 string
	AuditShipmentSink                string
	SignerURL                        string
	SignerClientCertFile             string
	SignerClientKeyFile              string
	SignerClientCAFile               string
	SignerKeyProvider                string
	SignerCACertFile                 string
	SignerCAKeyFile                  string
	SignerCAKeyPassphraseFile        string
	SignerPKCS11SignCommand          string
}

func Load() Config {
	cfg, err := LoadWithArgs(nil)
	if err != nil {
		return profileDefaults("")
	}
	return cfg
}

// LoadWithArgs applies the configuration precedence used in production: profile defaults, optional YAML, then env overrides.
// Keeping this order centralized prevents Lite/FULL profile drift between binaries.

// LoadFile resolves a server configuration file without applying environment overrides.
// It is used by offline planning tools that compare two explicit config files.
func LoadFile(path string) (Config, error) {
	fileValues, err := loadSimpleYAML(path)
	if err != nil {
		return Config{}, err
	}
	profile := strings.ToLower(strings.TrimSpace(fileValues["profile"]))
	cfg := profileDefaults(profile)
	cfg.ConfigFile = path
	if err := applyValues(&cfg, fileValues); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func LoadWithArgs(args []string) (Config, error) {
	configFile, err := parseConfigArgs(args)
	if err != nil {
		return Config{}, err
	}
	fileValues := map[string]string{}
	if configFile != "" {
		fileValues, err = loadSimpleYAML(configFile)
		if err != nil {
			return Config{}, err
		}
	}
	profile := strings.ToLower(strings.TrimSpace(os.Getenv("CUSTODIA_PROFILE")))
	if profile == "" {
		profile = strings.ToLower(strings.TrimSpace(fileValues["profile"]))
	}
	cfg := profileDefaults(profile)
	cfg.ConfigFile = configFile
	if err := applyValues(&cfg, fileValues); err != nil {
		return Config{}, err
	}
	applyEnv(&cfg)
	return cfg, nil
}

func profileDefaults(profile string) Config {
	cfg := Config{
		Profile:                       normalizedProfile(profile),
		APIAddr:                       ":8443",
		ServerURL:                     "",
		HealthAddr:                    "",
		WebAddr:                       ":9443",
		LogFile:                       "/var/log/custodia/custodia.log",
		StoreBackend:                  "memory",
		DatabaseURL:                   "",
		DevInsecureHTTP:               false,
		BootstrapClients:              map[string]string{},
		AdminClientIDs:                map[string]bool{},
		MaxEnvelopesPerSecret:         100,
		RateLimitBackend:              "memory",
		ClientRateLimitPerSecond:      100,
		GlobalRateLimitPerSecond:      5000,
		IPRateLimitPerSecond:          1000,
		HTTPReadTimeoutSeconds:        15,
		HTTPWriteTimeoutSeconds:       15,
		HTTPIdleTimeoutSeconds:        60,
		ShutdownTimeoutSeconds:        10,
		WebMFARequired:                false,
		WebSessionTTLSeconds:          900,
		WebPasskeyEnabled:             false,
		WebPasskeyRPID:                "localhost",
		WebPasskeyRPName:              "Custodia",
		WebPasskeyChallengeTTLSeconds: 300,
		DeploymentMode:                "single-region",
		DatabaseHATarget:              "external",
	}
	switch cfg.Profile {
	case ProfileLite:
		cfg.StoreBackend = "sqlite"
		cfg.DatabaseURL = "file:/var/lib/custodia/custodia.db"
		cfg.RateLimitBackend = "memory"
		cfg.DeploymentMode = "lite-single-node"
		cfg.DatabaseHATarget = "none"
		cfg.WebMFARequired = true
		cfg.WebPasskeyEnabled = false
	case ProfileFull:
		cfg.StoreBackend = "postgres"
		cfg.RateLimitBackend = "valkey"
		cfg.DeploymentMode = "production"
		cfg.DatabaseHATarget = "external"
		cfg.WebMFARequired = true
	}
	return cfg
}

func normalizedProfile(profile string) string {
	switch strings.ToLower(strings.TrimSpace(profile)) {
	case ProfileLite:
		return ProfileLite
	case ProfileFull:
		return ProfileFull
	case ProfileCustom:
		return ProfileCustom
	default:
		return ""
	}
}

func parseConfigArgs(args []string) (string, error) {
	for index := 0; index < len(args); index++ {
		arg := args[index]
		if arg == "--config" {
			if index+1 >= len(args) || strings.TrimSpace(args[index+1]) == "" {
				return "", errors.New("--config requires a path")
			}
			return args[index+1], nil
		}
		if strings.HasPrefix(arg, "--config=") {
			value := strings.TrimSpace(strings.TrimPrefix(arg, "--config="))
			if value == "" {
				return "", errors.New("--config requires a path")
			}
			return value, nil
		}
	}
	return "", nil
}

// loadSimpleYAML supports the auditable subset used by Custodia examples:
// structured runtime sections plus documented top-level identity lists.
// Unsupported sections and keys still fail closed.
func loadSimpleYAML(path string) (map[string]string, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	root := map[string]any{}
	if err := yaml.Unmarshal(payload, &root); err != nil {
		return nil, err
	}
	values := make(map[string]string)
	for key, raw := range root {
		key = strings.TrimSpace(key)
		if key == "" || raw == nil {
			continue
		}
		if section, ok := serverConfigSections[key]; ok {
			if err := flattenYAMLSection(values, key, raw, section); err != nil {
				return nil, err
			}
			continue
		}
		switch key {
		case "profile":
			value, err := yamlScalar(raw, key)
			if err != nil {
				return nil, err
			}
			values[key] = value
		case "bootstrap_clients":
			parsed, err := yamlBootstrapClients(raw)
			if err != nil {
				return nil, err
			}
			values[key] = strings.Join(parsed, ",")
		case "admin_client_ids":
			parsed, err := yamlStringList(raw, key)
			if err != nil {
				return nil, err
			}
			values[key] = strings.Join(parsed, ",")
		default:
			return nil, fmt.Errorf("unsupported top-level config key %q; use structured YAML sections", key)
		}
	}
	return values, nil
}

var serverConfigSections = map[string]map[string]string{
	"server": {
		"api_addr":    "api_addr",
		"url":         "server_url",
		"health_addr": "health_addr",
		"web_addr":    "web_addr",
		"log_file":    "log_file",
	},
	"storage": {
		"backend":      "store_backend",
		"database_url": "database_url",
	},
	"rate_limit": {
		"backend":           "rate_limit_backend",
		"valkey_url":        "valkey_url",
		"client_per_second": "client_rate_limit_per_second",
		"global_per_second": "global_rate_limit_per_second",
		"ip_per_second":     "ip_rate_limit_per_second",
	},
	"http": {
		"read_timeout_seconds":     "http_read_timeout_seconds",
		"write_timeout_seconds":    "http_write_timeout_seconds",
		"idle_timeout_seconds":     "http_idle_timeout_seconds",
		"shutdown_timeout_seconds": "shutdown_timeout_seconds",
	},
	"tls": {
		"cert_file":       "tls_cert_file",
		"key_file":        "tls_key_file",
		"client_ca_file":  "client_ca_file",
		"client_crl_file": "client_crl_file",
	},
	"web": {
		"mfa_required":                     "web_mfa_required",
		"totp_secret":                      "web_totp_secret",
		"session_secret":                   "web_session_secret",
		"session_ttl_seconds":              "web_session_ttl_seconds",
		"passkey_enabled":                  "web_passkey_enabled",
		"passkey_rp_id":                    "web_passkey_rp_id",
		"passkey_rp_name":                  "web_passkey_rp_name",
		"passkey_challenge_ttl_seconds":    "web_passkey_challenge_ttl_seconds",
		"passkey_assertion_verify_command": "web_passkey_assertion_verify_command",
	},
	"deployment": {
		"mode":                "deployment_mode",
		"database_ha_target":  "database_ha_target",
		"audit_shipment_sink": "audit_shipment_sink",
	},
	"signer": {
		"url":                    "signer_url",
		"client_cert_file":       "signer_client_cert_file",
		"client_key_file":        "signer_client_key_file",
		"client_ca_file":         "signer_client_ca_file",
		"key_provider":           "signer_key_provider",
		"ca_cert_file":           "signer_ca_cert_file",
		"ca_key_file":            "signer_ca_key_file",
		"ca_key_passphrase_file": "signer_ca_key_passphrase_file",
		"pkcs11_sign_command":    "signer_pkcs11_sign_command",
	},
	"limits": {
		"max_envelopes_per_secret": "max_envelopes_per_secret",
	},
	"security": {
		"dev_insecure_http": "dev_insecure_http",
	},
}

func flattenYAMLSection(values map[string]string, sectionName string, raw any, aliases map[string]string) error {
	section, ok := yamlMap(raw)
	if !ok {
		return fmt.Errorf("config section %q must be a mapping", sectionName)
	}
	for key, rawValue := range section {
		mapped, ok := aliases[key]
		if !ok {
			return fmt.Errorf("unsupported config key %q in section %q", key, sectionName)
		}
		value, err := yamlScalar(rawValue, sectionName+"."+key)
		if err != nil {
			return err
		}
		values[mapped] = value
	}
	return nil
}

func yamlBootstrapClients(raw any) ([]string, error) {
	switch value := raw.(type) {
	case string:
		return []string{value}, nil
	case []any:
		items := []string{}
		for _, item := range value {
			entry, ok := yamlMap(item)
			if !ok {
				return nil, fmt.Errorf("bootstrap_clients entries must be mappings")
			}
			clientID, err := yamlRequiredScalar(entry, "client_id", "bootstrap_clients")
			if err != nil {
				return nil, err
			}
			subject, err := yamlRequiredScalar(entry, "mtls_subject", "bootstrap_clients")
			if err != nil {
				return nil, err
			}
			for key := range entry {
				if key != "client_id" && key != "mtls_subject" {
					return nil, fmt.Errorf("unsupported bootstrap_clients key %q", key)
				}
			}
			items = append(items, clientID+":"+subject)
		}
		return items, nil
	default:
		return nil, fmt.Errorf("bootstrap_clients must be a string or list of mappings")
	}
}

func yamlStringList(raw any, key string) ([]string, error) {
	switch value := raw.(type) {
	case string:
		return []string{value}, nil
	case []any:
		items := []string{}
		for _, item := range value {
			text, err := yamlScalar(item, key)
			if err != nil {
				return nil, err
			}
			items = append(items, text)
		}
		return items, nil
	default:
		return nil, fmt.Errorf("%s must be a string or list of strings", key)
	}
}

func yamlRequiredScalar(values map[string]any, key, parent string) (string, error) {
	raw, ok := values[key]
	if !ok {
		return "", fmt.Errorf("%s entries require %s", parent, key)
	}
	text, err := yamlScalar(raw, parent+"."+key)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(text) == "" {
		return "", fmt.Errorf("%s entries require %s", parent, key)
	}
	return text, nil
}

func yamlMap(raw any) (map[string]any, bool) {
	mapped, ok := raw.(map[string]any)
	return mapped, ok
}

func yamlScalar(raw any, key string) (string, error) {
	switch value := raw.(type) {
	case string:
		return value, nil
	case bool:
		return strconv.FormatBool(value), nil
	case int:
		return strconv.Itoa(value), nil
	case int64:
		return strconv.FormatInt(value, 10), nil
	case uint64:
		return strconv.FormatUint(value, 10), nil
	case float64:
		if value == float64(int64(value)) {
			return strconv.FormatInt(int64(value), 10), nil
		}
		return "", fmt.Errorf("%s must be a scalar string, bool or integer", key)
	default:
		return "", fmt.Errorf("%s must be a scalar string, bool or integer", key)
	}
}

func parseYAMLStringList(lines []string, start int) ([]string, int, error) {
	values := []string{}
	for index := start; index < len(lines); index++ {
		raw := stripComment(lines[index])
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if leadingSpaces(raw) == 0 {
			return values, index, nil
		}
		if !strings.HasPrefix(line, "- ") {
			return nil, 0, fmt.Errorf("unsupported YAML syntax on line %d", index+1)
		}
		value := strings.TrimSpace(strings.TrimPrefix(line, "- "))
		if value == "" {
			return nil, 0, fmt.Errorf("unsupported YAML syntax on line %d", index+1)
		}
		values = append(values, unquote(value))
	}
	return values, len(lines), nil
}

func parseYAMLBootstrapClients(lines []string, start int) ([]string, int, error) {
	items := []string{}
	current := map[string]string{}
	flush := func() error {
		if len(current) == 0 {
			return nil
		}
		clientID := strings.TrimSpace(current["client_id"])
		subject := strings.TrimSpace(current["mtls_subject"])
		if clientID == "" || subject == "" {
			return fmt.Errorf("bootstrap_clients entries require client_id and mtls_subject")
		}
		items = append(items, clientID+":"+subject)
		current = map[string]string{}
		return nil
	}

	for index := start; index < len(lines); index++ {
		raw := stripComment(lines[index])
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if leadingSpaces(raw) == 0 {
			if err := flush(); err != nil {
				return nil, 0, err
			}
			return items, index, nil
		}
		if strings.HasPrefix(line, "- ") {
			if err := flush(); err != nil {
				return nil, 0, err
			}
			entry := strings.TrimSpace(strings.TrimPrefix(line, "- "))
			if entry == "" {
				continue
			}
			key, value, ok := strings.Cut(entry, ":")
			if !ok {
				return nil, 0, fmt.Errorf("invalid YAML line %d", index+1)
			}
			current[strings.TrimSpace(key)] = unquote(strings.TrimSpace(value))
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok || strings.TrimSpace(key) == "" {
			return nil, 0, fmt.Errorf("invalid YAML line %d", index+1)
		}
		switch strings.TrimSpace(key) {
		case "client_id", "mtls_subject":
			current[strings.TrimSpace(key)] = unquote(strings.TrimSpace(value))
		default:
			return nil, 0, fmt.Errorf("unsupported bootstrap_clients key %q on line %d", strings.TrimSpace(key), index+1)
		}
	}
	if err := flush(); err != nil {
		return nil, 0, err
	}
	return items, len(lines), nil
}

func leadingSpaces(line string) int {
	count := 0
	for _, char := range line {
		if char != ' ' {
			return count
		}
		count++
	}
	return count
}

func stripComment(line string) string {
	inSingle := false
	inDouble := false
	for index, char := range line {
		switch char {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '#':
			if !inSingle && !inDouble {
				return line[:index]
			}
		}
	}
	return line
}

func unquote(value string) string {
	if len(value) >= 2 {
		if (value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'') {
			return value[1 : len(value)-1]
		}
	}
	return value
}

func applyValues(cfg *Config, values map[string]string) error {
	for key, value := range values {
		switch key {
		case "profile":
			cfg.Profile = normalizedProfile(value)
		case "api_addr":
			cfg.APIAddr = value
		case "server_url":
			cfg.ServerURL = value
		case "health_addr":
			cfg.HealthAddr = value
		case "web_addr":
			cfg.WebAddr = value
		case "log_file":
			cfg.LogFile = value
		case "store_backend":
			cfg.StoreBackend = value
		case "database_url":
			cfg.DatabaseURL = value
		case "tls_cert_file":
			cfg.TLSCertFile = value
		case "tls_key_file":
			cfg.TLSKeyFile = value
		case "client_ca_file":
			cfg.ClientCAFile = value
		case "client_crl_file":
			cfg.ClientCRLFile = value
		case "dev_insecure_http":
			parsed, err := strconv.ParseBool(value)
			if err != nil {
				return fmt.Errorf("invalid dev_insecure_http: %w", err)
			}
			cfg.DevInsecureHTTP = parsed
		case "bootstrap_clients":
			cfg.BootstrapClients = parsePairs(value)
		case "admin_client_ids":
			cfg.AdminClientIDs = parseSet(value)
		case "max_envelopes_per_secret":
			cfg.MaxEnvelopesPerSecret = parsePositiveInt(value, cfg.MaxEnvelopesPerSecret)
		case "rate_limit_backend":
			cfg.RateLimitBackend = value
		case "valkey_url":
			cfg.ValkeyURL = value
		case "client_rate_limit_per_second":
			cfg.ClientRateLimitPerSecond = parsePositiveInt(value, cfg.ClientRateLimitPerSecond)
		case "global_rate_limit_per_second":
			cfg.GlobalRateLimitPerSecond = parsePositiveInt(value, cfg.GlobalRateLimitPerSecond)
		case "ip_rate_limit_per_second":
			cfg.IPRateLimitPerSecond = parsePositiveInt(value, cfg.IPRateLimitPerSecond)
		case "http_read_timeout_seconds":
			cfg.HTTPReadTimeoutSeconds = parsePositiveInt(value, cfg.HTTPReadTimeoutSeconds)
		case "http_write_timeout_seconds":
			cfg.HTTPWriteTimeoutSeconds = parsePositiveInt(value, cfg.HTTPWriteTimeoutSeconds)
		case "http_idle_timeout_seconds":
			cfg.HTTPIdleTimeoutSeconds = parsePositiveInt(value, cfg.HTTPIdleTimeoutSeconds)
		case "shutdown_timeout_seconds":
			cfg.ShutdownTimeoutSeconds = parsePositiveInt(value, cfg.ShutdownTimeoutSeconds)
		case "web_mfa_required":
			parsed, err := strconv.ParseBool(value)
			if err != nil {
				return fmt.Errorf("invalid web_mfa_required: %w", err)
			}
			cfg.WebMFARequired = parsed
		case "web_totp_secret":
			cfg.WebTOTPSecret = value
		case "web_session_secret":
			cfg.WebSessionSecret = value
		case "web_session_ttl_seconds":
			cfg.WebSessionTTLSeconds = parsePositiveInt(value, cfg.WebSessionTTLSeconds)
		case "web_passkey_enabled":
			parsed, err := strconv.ParseBool(value)
			if err != nil {
				return fmt.Errorf("invalid web_passkey_enabled: %w", err)
			}
			cfg.WebPasskeyEnabled = parsed
		case "web_passkey_rp_id":
			cfg.WebPasskeyRPID = value
		case "web_passkey_rp_name":
			cfg.WebPasskeyRPName = value
		case "web_passkey_challenge_ttl_seconds":
			cfg.WebPasskeyChallengeTTLSeconds = parsePositiveInt(value, cfg.WebPasskeyChallengeTTLSeconds)
		case "web_passkey_assertion_verify_command":
			cfg.WebPasskeyAssertionVerifyCommand = value
		case "deployment_mode":
			cfg.DeploymentMode = value
		case "database_ha_target":
			cfg.DatabaseHATarget = value
		case "audit_shipment_sink":
			cfg.AuditShipmentSink = value
		case "signer_url":
			cfg.SignerURL = value
		case "signer_client_cert_file":
			cfg.SignerClientCertFile = value
		case "signer_client_key_file":
			cfg.SignerClientKeyFile = value
		case "signer_client_ca_file":
			cfg.SignerClientCAFile = value
		case "signer_key_provider":
			cfg.SignerKeyProvider = value
		case "signer_ca_cert_file":
			cfg.SignerCACertFile = value
		case "signer_ca_key_file":
			cfg.SignerCAKeyFile = value
		case "signer_ca_key_passphrase_file":
			cfg.SignerCAKeyPassphraseFile = value
		case "signer_pkcs11_sign_command":
			cfg.SignerPKCS11SignCommand = value
		default:
			return fmt.Errorf("unsupported config key %q", key)
		}
	}
	return nil
}

func applyEnv(cfg *Config) {
	if value := os.Getenv("CUSTODIA_PROFILE"); strings.TrimSpace(value) != "" {
		cfg.Profile = normalizedProfile(value)
	}
	cfg.APIAddr = env("CUSTODIA_API_ADDR", cfg.APIAddr)
	cfg.ServerURL = env("CUSTODIA_SERVER_URL", cfg.ServerURL)
	cfg.HealthAddr = env("CUSTODIA_HEALTH_ADDR", cfg.HealthAddr)
	cfg.WebAddr = env("CUSTODIA_WEB_ADDR", cfg.WebAddr)
	cfg.LogFile = env("CUSTODIA_LOG_FILE", cfg.LogFile)
	cfg.StoreBackend = env("CUSTODIA_STORE_BACKEND", cfg.StoreBackend)
	cfg.DatabaseURL = env("CUSTODIA_DATABASE_URL", cfg.DatabaseURL)
	cfg.TLSCertFile = env("CUSTODIA_TLS_CERT_FILE", cfg.TLSCertFile)
	cfg.TLSKeyFile = env("CUSTODIA_TLS_KEY_FILE", cfg.TLSKeyFile)
	cfg.ClientCAFile = env("CUSTODIA_CLIENT_CA_FILE", cfg.ClientCAFile)
	cfg.ClientCRLFile = env("CUSTODIA_CLIENT_CRL_FILE", cfg.ClientCRLFile)
	cfg.DevInsecureHTTP = envBool("CUSTODIA_DEV_INSECURE_HTTP", cfg.DevInsecureHTTP)
	if value := os.Getenv("CUSTODIA_BOOTSTRAP_CLIENTS"); strings.TrimSpace(value) != "" {
		cfg.BootstrapClients = envPairs("CUSTODIA_BOOTSTRAP_CLIENTS")
	}
	if value := os.Getenv("CUSTODIA_ADMIN_CLIENT_IDS"); strings.TrimSpace(value) != "" {
		cfg.AdminClientIDs = envSet("CUSTODIA_ADMIN_CLIENT_IDS")
	}
	cfg.MaxEnvelopesPerSecret = envInt("CUSTODIA_MAX_ENVELOPES_PER_SECRET", cfg.MaxEnvelopesPerSecret)
	cfg.RateLimitBackend = env("CUSTODIA_RATE_LIMIT_BACKEND", cfg.RateLimitBackend)
	cfg.ValkeyURL = env("CUSTODIA_VALKEY_URL", cfg.ValkeyURL)
	cfg.ClientRateLimitPerSecond = envInt("CUSTODIA_CLIENT_RATE_LIMIT_PER_SECOND", cfg.ClientRateLimitPerSecond)
	cfg.GlobalRateLimitPerSecond = envInt("CUSTODIA_GLOBAL_RATE_LIMIT_PER_SECOND", cfg.GlobalRateLimitPerSecond)
	cfg.IPRateLimitPerSecond = envInt("CUSTODIA_IP_RATE_LIMIT_PER_SECOND", cfg.IPRateLimitPerSecond)
	cfg.HTTPReadTimeoutSeconds = envInt("CUSTODIA_HTTP_READ_TIMEOUT_SECONDS", cfg.HTTPReadTimeoutSeconds)
	cfg.HTTPWriteTimeoutSeconds = envInt("CUSTODIA_HTTP_WRITE_TIMEOUT_SECONDS", cfg.HTTPWriteTimeoutSeconds)
	cfg.HTTPIdleTimeoutSeconds = envInt("CUSTODIA_HTTP_IDLE_TIMEOUT_SECONDS", cfg.HTTPIdleTimeoutSeconds)
	cfg.ShutdownTimeoutSeconds = envInt("CUSTODIA_SHUTDOWN_TIMEOUT_SECONDS", cfg.ShutdownTimeoutSeconds)
	cfg.WebMFARequired = envBool("CUSTODIA_WEB_MFA_REQUIRED", cfg.WebMFARequired)
	cfg.WebTOTPSecret = env("CUSTODIA_WEB_TOTP_SECRET", cfg.WebTOTPSecret)
	cfg.WebSessionSecret = env("CUSTODIA_WEB_SESSION_SECRET", cfg.WebSessionSecret)
	cfg.WebSessionTTLSeconds = envInt("CUSTODIA_WEB_SESSION_TTL_SECONDS", cfg.WebSessionTTLSeconds)
	cfg.WebPasskeyEnabled = envBool("CUSTODIA_WEB_PASSKEY_ENABLED", cfg.WebPasskeyEnabled)
	cfg.WebPasskeyRPID = env("CUSTODIA_WEB_PASSKEY_RP_ID", cfg.WebPasskeyRPID)
	cfg.WebPasskeyRPName = env("CUSTODIA_WEB_PASSKEY_RP_NAME", cfg.WebPasskeyRPName)
	cfg.WebPasskeyChallengeTTLSeconds = envInt("CUSTODIA_WEB_PASSKEY_CHALLENGE_TTL_SECONDS", cfg.WebPasskeyChallengeTTLSeconds)
	cfg.WebPasskeyAssertionVerifyCommand = env("CUSTODIA_WEB_PASSKEY_ASSERTION_VERIFY_COMMAND", cfg.WebPasskeyAssertionVerifyCommand)
	cfg.DeploymentMode = env("CUSTODIA_DEPLOYMENT_MODE", cfg.DeploymentMode)
	cfg.DatabaseHATarget = env("CUSTODIA_DATABASE_HA_TARGET", cfg.DatabaseHATarget)
	cfg.AuditShipmentSink = env("CUSTODIA_AUDIT_SHIPMENT_SINK", cfg.AuditShipmentSink)
	cfg.SignerURL = env("CUSTODIA_SIGNER_URL", cfg.SignerURL)
	cfg.SignerClientCertFile = env("CUSTODIA_SIGNER_CLIENT_CERT_FILE", cfg.SignerClientCertFile)
	cfg.SignerClientKeyFile = env("CUSTODIA_SIGNER_CLIENT_KEY_FILE", cfg.SignerClientKeyFile)
	cfg.SignerClientCAFile = env("CUSTODIA_SIGNER_CLIENT_CA_FILE", cfg.SignerClientCAFile)
	cfg.SignerKeyProvider = env("CUSTODIA_SIGNER_KEY_PROVIDER", cfg.SignerKeyProvider)
	cfg.SignerCACertFile = env("CUSTODIA_SIGNER_CA_CERT_FILE", cfg.SignerCACertFile)
	cfg.SignerCAKeyFile = env("CUSTODIA_SIGNER_CA_KEY_FILE", cfg.SignerCAKeyFile)
	cfg.SignerCAKeyPassphraseFile = env("CUSTODIA_SIGNER_CA_KEY_PASSPHRASE_FILE", cfg.SignerCAKeyPassphraseFile)
	cfg.SignerPKCS11SignCommand = env("CUSTODIA_SIGNER_PKCS11_SIGN_COMMAND", cfg.SignerPKCS11SignCommand)
}

func parsePositiveInt(value string, fallback int) int {
	parsed, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

func parseSet(value string) map[string]bool {
	set := make(map[string]bool)
	for _, part := range strings.Split(value, ",") {
		item := strings.TrimSpace(part)
		if item != "" {
			set[item] = true
		}
	}
	return set
}

func parsePairs(value string) map[string]string {
	pairs := make(map[string]string)
	for _, part := range strings.Split(value, ",") {
		item := strings.TrimSpace(part)
		if item == "" {
			continue
		}
		left, right, ok := strings.Cut(item, ":")
		if !ok {
			continue
		}
		clientID := strings.TrimSpace(left)
		subject := strings.TrimSpace(right)
		if clientID != "" && subject != "" {
			pairs[clientID] = subject
		}
	}
	return pairs
}

func env(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func envBool(key string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func envInt(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

func envSet(key string) map[string]bool {
	return parseSet(os.Getenv(key))
}

func envPairs(key string) map[string]string {
	return parsePairs(os.Getenv(key))
}
