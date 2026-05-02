package config

import (
	"os"
	"strconv"
	"strings"
)

type Config struct {
	APIAddr                  string
	WebAddr                  string
	StoreBackend             string
	DatabaseURL              string
	TLSCertFile              string
	TLSKeyFile               string
	ClientCAFile             string
	DevInsecureHTTP          bool
	BootstrapClients         map[string]string
	AdminClientIDs           map[string]bool
	MaxEnvelopesPerSecret    int
	RateLimitBackend         string
	ValkeyURL                string
	ClientRateLimitPerSecond int
	GlobalRateLimitPerSecond int
}

func Load() Config {
	return Config{
		APIAddr:                  env("CUSTODIA_API_ADDR", ":8443"),
		WebAddr:                  env("CUSTODIA_WEB_ADDR", ":9443"),
		StoreBackend:             env("CUSTODIA_STORE_BACKEND", "memory"),
		DatabaseURL:              os.Getenv("CUSTODIA_DATABASE_URL"),
		TLSCertFile:              os.Getenv("CUSTODIA_TLS_CERT_FILE"),
		TLSKeyFile:               os.Getenv("CUSTODIA_TLS_KEY_FILE"),
		ClientCAFile:             os.Getenv("CUSTODIA_CLIENT_CA_FILE"),
		DevInsecureHTTP:          envBool("CUSTODIA_DEV_INSECURE_HTTP", false),
		BootstrapClients:         envPairs("CUSTODIA_BOOTSTRAP_CLIENTS"),
		AdminClientIDs:           envSet("CUSTODIA_ADMIN_CLIENT_IDS"),
		MaxEnvelopesPerSecret:    envInt("CUSTODIA_MAX_ENVELOPES_PER_SECRET", 100),
		RateLimitBackend:         env("CUSTODIA_RATE_LIMIT_BACKEND", "memory"),
		ValkeyURL:                os.Getenv("CUSTODIA_VALKEY_URL"),
		ClientRateLimitPerSecond: envInt("CUSTODIA_CLIENT_RATE_LIMIT_PER_SECOND", 100),
		GlobalRateLimitPerSecond: envInt("CUSTODIA_GLOBAL_RATE_LIMIT_PER_SECOND", 5000),
	}
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
	set := make(map[string]bool)
	for _, part := range strings.Split(os.Getenv(key), ",") {
		value := strings.TrimSpace(part)
		if value != "" {
			set[value] = true
		}
	}
	return set
}

func envPairs(key string) map[string]string {
	pairs := make(map[string]string)
	for _, part := range strings.Split(os.Getenv(key), ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		pieces := strings.SplitN(part, ":", 2)
		if len(pieces) != 2 {
			continue
		}
		clientID := strings.TrimSpace(pieces[0])
		subject := strings.TrimSpace(pieces[1])
		if clientID != "" && subject != "" {
			pairs[clientID] = subject
		}
	}
	return pairs
}
