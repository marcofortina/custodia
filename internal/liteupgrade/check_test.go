package liteupgrade

import (
	"testing"

	"custodia/internal/productioncheck"
)

func TestCheckAcceptsPlannedLiteToFullUpgrade(t *testing.T) {
	findings := Check(map[string]string{
		"CUSTODIA_PROFILE":             "lite",
		"CUSTODIA_STORE_BACKEND":       "sqlite",
		"CUSTODIA_DATABASE_URL":        "file:/var/lib/custodia/custodia.db",
		"CUSTODIA_SIGNER_KEY_PROVIDER": "file",
	}, map[string]string{
		"CUSTODIA_PROFILE":             "full",
		"CUSTODIA_STORE_BACKEND":       "postgres",
		"CUSTODIA_DATABASE_URL":        "postgres://custodia@db/custodia",
		"CUSTODIA_RATE_LIMIT_BACKEND":  "valkey",
		"CUSTODIA_VALKEY_URL":          "rediss://valkey:6379/0",
		"CUSTODIA_SIGNER_KEY_PROVIDER": "pkcs11",
		"CUSTODIA_AUDIT_SHIPMENT_SINK": "s3-object-lock://custodia-audit",
		"CUSTODIA_DATABASE_HA_TARGET":  "cockroachdb-multi-region",
	})
	if productioncheck.HasCritical(findings) {
		t.Fatalf("expected no critical findings, got %#v", findings)
	}
}

func TestCheckRejectsMissingLiteSourceAndFullTarget(t *testing.T) {
	findings := Check(map[string]string{
		"CUSTODIA_PROFILE":       "full",
		"CUSTODIA_STORE_BACKEND": "postgres",
	}, map[string]string{
		"CUSTODIA_PROFILE":       "lite",
		"CUSTODIA_STORE_BACKEND": "sqlite",
	})
	for _, code := range []string{"lite_source_profile", "lite_source_store", "full_target_profile", "full_target_store"} {
		if !hasFinding(findings, code) {
			t.Fatalf("missing finding %s in %#v", code, findings)
		}
	}
	if !productioncheck.HasCritical(findings) {
		t.Fatalf("expected critical findings, got %#v", findings)
	}
}

func hasFinding(findings []productioncheck.Finding, code string) bool {
	for _, finding := range findings {
		if finding.Code == code {
			return true
		}
	}
	return false
}
