// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

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
