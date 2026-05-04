// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package crldist

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
)

var ErrInvalidCRL = errors.New("invalid certificate revocation list")

func LoadPEM(path string) ([]byte, *x509.RevocationList, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	block, _ := pem.Decode(payload)
	if block == nil || block.Type != "X509 CRL" {
		return nil, nil, ErrInvalidCRL
	}
	list, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		return nil, nil, ErrInvalidCRL
	}
	return payload, list, nil
}
