// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package revocationresponder

import (
	"crypto/x509"
	"errors"
	"math/big"
	"strings"
	"time"
)

const (
	StatusGood    = "good"
	StatusRevoked = "revoked"
)

var ErrInvalidSerial = errors.New("invalid certificate serial")

type Status struct {
	SerialHex    string     `json:"serial_hex"`
	Status       string     `json:"status"`
	ThisUpdate   time.Time  `json:"this_update"`
	NextUpdate   time.Time  `json:"next_update"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
	RevokedCount int        `json:"revoked_count"`
}

func CheckCRL(list *x509.RevocationList, serialHex string) (*Status, error) {
	serial, normalized, err := parseSerialHex(serialHex)
	if err != nil {
		return nil, err
	}
	status := &Status{
		SerialHex:    normalized,
		Status:       StatusGood,
		ThisUpdate:   list.ThisUpdate,
		NextUpdate:   list.NextUpdate,
		RevokedCount: len(list.RevokedCertificateEntries),
	}
	for _, entry := range list.RevokedCertificateEntries {
		if entry.SerialNumber != nil && entry.SerialNumber.Cmp(serial) == 0 {
			revokedAt := entry.RevocationTime
			status.Status = StatusRevoked
			status.RevokedAt = &revokedAt
			return status, nil
		}
	}
	return status, nil
}

func parseSerialHex(value string) (*big.Int, string, error) {
	serialHex := strings.TrimSpace(value)
	serialHex = strings.TrimPrefix(serialHex, "0x")
	serialHex = strings.TrimPrefix(serialHex, "0X")
	serialHex = strings.ToLower(serialHex)
	if serialHex == "" {
		return nil, "", ErrInvalidSerial
	}
	serial := new(big.Int)
	if _, ok := serial.SetString(serialHex, 16); !ok || serial.Sign() <= 0 {
		return nil, "", ErrInvalidSerial
	}
	return serial, serial.Text(16), nil
}
