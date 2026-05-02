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
