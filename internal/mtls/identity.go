// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package mtls

import (
	"crypto/x509"
	"errors"
	"net/http"
	"strings"
)

var ErrMissingClientCertificate = errors.New("missing client certificate")
var ErrMissingClientIdentity = errors.New("missing client identity in certificate")

func ClientIDFromRequest(r *http.Request) (string, error) {
	if r == nil || r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return "", ErrMissingClientCertificate
	}
	return ClientIDFromCertificate(r.TLS.PeerCertificates[0])
}

func ClientIDFromCertificate(cert *x509.Certificate) (string, error) {
	if cert == nil {
		return "", ErrMissingClientCertificate
	}
	for _, dnsName := range cert.DNSNames {
		if trimmed := strings.TrimSpace(dnsName); trimmed != "" {
			return trimmed, nil
		}
	}
	for _, uri := range cert.URIs {
		if uri != nil && strings.TrimSpace(uri.String()) != "" {
			return uri.String(), nil
		}
	}
	if strings.TrimSpace(cert.Subject.CommonName) != "" {
		return strings.TrimSpace(cert.Subject.CommonName), nil
	}
	return "", ErrMissingClientIdentity
}
