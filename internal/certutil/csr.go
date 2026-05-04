// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package certutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"

	"custodia/internal/model"
)

var ErrInvalidClientID = errors.New("invalid client id")

type ClientCSR struct {
	PrivateKeyPEM []byte
	CSRPem        []byte
}

func GenerateClientCSR(clientID string) (*ClientCSR, error) {
	if !model.ValidClientID(clientID) {
		return nil, ErrInvalidClientID
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: clientID},
		DNSNames: []string{clientID},
	}, privateKey)
	if err != nil {
		return nil, err
	}
	return &ClientCSR{
		PrivateKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		CSRPem:        pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}),
	}, nil
}
