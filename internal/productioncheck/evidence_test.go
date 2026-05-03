package productioncheck

import "testing"

func TestCheckExternalEvidenceRequiresEveryEvidenceFile(t *testing.T) {
	findings := CheckExternalEvidence(map[string]string{})
	if len(findings) != len(RequiredEvidenceKeys()) {
		t.Fatalf("expected %d evidence findings, got %d", len(RequiredEvidenceKeys()), len(findings))
	}
	for _, finding := range findings {
		if finding.Severity != SeverityCritical {
			t.Fatalf("expected critical finding, got %+v", finding)
		}
	}
}

func TestCheckExternalEvidenceAcceptsConfiguredEvidenceFiles(t *testing.T) {
	env := map[string]string{}
	for _, key := range RequiredEvidenceKeys() {
		env[key] = "/evidence/" + key + ".json"
	}
	findings := CheckExternalEvidence(env)
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %+v", findings)
	}
}
