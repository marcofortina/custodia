// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package audit

import (
	"bytes"
	"encoding/hex"

	"custodia/internal/model"
)

type VerificationResult struct {
	Valid          bool   `json:"valid"`
	VerifiedEvents int    `json:"verified_events"`
	HeadHash       string `json:"head_hash,omitempty"`
	FailureIndex   int    `json:"failure_index,omitempty"`
	FailureReason  string `json:"failure_reason,omitempty"`
}

func VerifyChain(events []model.AuditEvent) VerificationResult {
	result := VerificationResult{Valid: true, VerifiedEvents: len(events), FailureIndex: -1}
	var previousHash []byte
	for index, event := range events {
		if index > 0 && !bytes.Equal(event.PreviousHash, previousHash) {
			return VerificationResult{
				Valid:          false,
				VerifiedEvents: index,
				FailureIndex:   index,
				FailureReason:  "previous_hash_mismatch",
			}
		}
		recomputed := ComputeHash(event.PreviousHash, event)
		if !bytes.Equal(recomputed, event.EventHash) {
			return VerificationResult{
				Valid:          false,
				VerifiedEvents: index,
				FailureIndex:   index,
				FailureReason:  "event_hash_mismatch",
			}
		}
		previousHash = event.EventHash
	}
	if len(events) > 0 {
		result.HeadHash = hex.EncodeToString(events[len(events)-1].EventHash)
	}
	return result
}
