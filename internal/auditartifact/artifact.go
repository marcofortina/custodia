// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package auditartifact

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

var (
	ErrDigestMismatch = errors.New("audit export digest mismatch")
	ErrEventMismatch  = errors.New("audit export event count mismatch")
	ErrInvalidDigest  = errors.New("invalid audit export digest")
	ErrInvalidCount   = errors.New("invalid audit export event count")
)

type Verification struct {
	SHA256         string `json:"sha256"`
	ExpectedSHA256 string `json:"expected_sha256"`
	Events         int    `json:"events"`
	ExpectedEvents int    `json:"expected_events"`
	Valid          bool   `json:"valid"`
}

// Verify binds the artifact body to both digest and event-count metadata. The
// count check catches empty/truncated JSONL exports with a valid-looking checksum.
func Verify(body []byte, expectedSHA256 string, expectedEvents string) (Verification, error) {
	expectedSHA256 = strings.TrimSpace(expectedSHA256)
	if len(expectedSHA256) != sha256.Size*2 {
		return Verification{}, ErrInvalidDigest
	}
	if _, err := hex.DecodeString(expectedSHA256); err != nil {
		return Verification{}, ErrInvalidDigest
	}
	expectedCount, err := strconv.Atoi(strings.TrimSpace(expectedEvents))
	if err != nil || expectedCount < 0 {
		return Verification{}, ErrInvalidCount
	}
	digest := sha256.Sum256(body)
	actualDigest := hex.EncodeToString(digest[:])
	actualCount := CountJSONLLines(body)
	result := Verification{
		SHA256:         actualDigest,
		ExpectedSHA256: expectedSHA256,
		Events:         actualCount,
		ExpectedEvents: expectedCount,
		Valid:          actualDigest == expectedSHA256 && actualCount == expectedCount,
	}
	if actualDigest != expectedSHA256 {
		return result, fmt.Errorf("%w", ErrDigestMismatch)
	}
	if actualCount != expectedCount {
		return result, fmt.Errorf("%w", ErrEventMismatch)
	}
	return result, nil
}

func CountJSONLLines(body []byte) int {
	scanner := bufio.NewScanner(bytes.NewReader(body))
	count := 0
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) != "" {
			count++
		}
	}
	return count
}
