// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package audit

import (
	"bytes"
	"testing"
	"time"

	"custodia/internal/model"
)

func TestComputeHashDependsOnPreviousHash(t *testing.T) {
	event := model.AuditEvent{
		EventID:      "evt-1",
		OccurredAt:   time.Unix(10, 0).UTC(),
		Action:       "secret.read",
		ResourceType: "secret",
		Outcome:      "success",
	}

	first := ComputeHash(nil, event)
	second := ComputeHash([]byte("previous"), event)

	if bytes.Equal(first, second) {
		t.Fatal("expected previous hash to affect the audit event hash")
	}
}
