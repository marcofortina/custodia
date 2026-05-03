package productioncheck

import "strings"

var requiredEvidence = []struct {
	key     string
	code    string
	message string
}{
	{"CUSTODIA_EVIDENCE_HSM_ATTESTATION_FILE", "evidence_hsm_attestation", "HSM/PKCS#11 attestation evidence is required for Fort Knox production closure"},
	{"CUSTODIA_EVIDENCE_WORM_RETENTION_FILE", "evidence_worm_retention", "WORM/object-lock retention evidence is required for immutable audit closure"},
	{"CUSTODIA_EVIDENCE_DATABASE_HA_FILE", "evidence_database_ha", "database HA/failover evidence is required for HA/DR closure"},
	{"CUSTODIA_EVIDENCE_VALKEY_CLUSTER_FILE", "evidence_valkey_cluster", "Valkey cluster evidence is required for active-active rate-limit closure"},
	{"CUSTODIA_EVIDENCE_ZERO_TRUST_NETWORK_FILE", "evidence_zero_trust_network", "zero-trust network policy evidence is required for cluster closure"},
	{"CUSTODIA_EVIDENCE_AIR_GAP_BACKUP_FILE", "evidence_air_gap_backup", "air-gapped backup evidence is required for Fort Knox backup closure"},
	{"CUSTODIA_EVIDENCE_PEN_TEST_FILE", "evidence_pen_test", "penetration-test evidence is required for Fort Knox production closure"},
	{"CUSTODIA_EVIDENCE_FORMAL_VERIFICATION_FILE", "evidence_formal_verification", "formal verification/TLC execution evidence is required for protocol closure"},
	{"CUSTODIA_EVIDENCE_REVOCATION_DRILL_FILE", "evidence_revocation_drill", "CRL/OCSP revocation drill evidence is required for revocation closure"},
	{"CUSTODIA_EVIDENCE_RELEASE_CHECK_FILE", "evidence_release_check", "release-check evidence is required for release closure"},
}

func CheckExternalEvidence(env map[string]string) []Finding {
	var findings []Finding
	for _, requirement := range requiredEvidence {
		if strings.TrimSpace(env[requirement.key]) == "" {
			findings = append(findings, Finding{Code: requirement.code, Severity: SeverityCritical, Message: requirement.message})
		}
	}
	return findings
}

func RequiredEvidenceKeys() []string {
	keys := make([]string, 0, len(requiredEvidence))
	for _, requirement := range requiredEvidence {
		keys = append(keys, requirement.key)
	}
	return keys
}
