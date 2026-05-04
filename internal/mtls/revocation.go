// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package mtls

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"sync"
	"time"
)

var ErrRevokedClientCertificate = errors.New("revoked client certificate")

type ClientCRLStatus struct {
	Source       string
	Issuer       string
	ThisUpdate   time.Time
	NextUpdate   time.Time
	RevokedCount int
}

func LoadClientCRLStatus(crlFile string, caPEM []byte) (ClientCRLStatus, error) {
	crlPEM, err := os.ReadFile(crlFile)
	if err != nil {
		return ClientCRLStatus{}, fmt.Errorf("read client CRL: %w", err)
	}
	issuers, err := parseCertificatesFromPEM(caPEM)
	if err != nil {
		return ClientCRLStatus{}, err
	}
	status := ClientCRLStatus{Source: crlFile}
	parsedAny := false
	for len(crlPEM) > 0 {
		var block *pem.Block
		block, crlPEM = pem.Decode(crlPEM)
		if block == nil {
			break
		}
		if block.Type != "X509 CRL" {
			continue
		}
		parsedAny = true
		list, err := x509.ParseRevocationList(block.Bytes)
		if err != nil {
			return ClientCRLStatus{}, fmt.Errorf("parse client CRL: %w", err)
		}
		if err := verifyRevocationList(list, issuers); err != nil {
			return ClientCRLStatus{}, err
		}
		if status.Issuer == "" {
			status.Issuer = list.Issuer.String()
		}
		if status.ThisUpdate.IsZero() || list.ThisUpdate.Before(status.ThisUpdate) {
			status.ThisUpdate = list.ThisUpdate
		}
		if status.NextUpdate.IsZero() || list.NextUpdate.Before(status.NextUpdate) {
			status.NextUpdate = list.NextUpdate
		}
		status.RevokedCount += len(list.RevokedCertificateEntries)
	}
	if !parsedAny {
		return ClientCRLStatus{}, fmt.Errorf("client CRL file does not contain a valid PEM CRL")
	}
	return status, nil
}

func LoadRevokedClientSerials(crlFile string, caPEM []byte) (map[string]struct{}, error) {
	crlPEM, err := os.ReadFile(crlFile)
	if err != nil {
		return nil, fmt.Errorf("read client CRL: %w", err)
	}
	issuers, err := parseCertificatesFromPEM(caPEM)
	if err != nil {
		return nil, err
	}
	revoked := make(map[string]struct{})
	parsedAny := false
	for len(crlPEM) > 0 {
		var block *pem.Block
		block, crlPEM = pem.Decode(crlPEM)
		if block == nil {
			break
		}
		if block.Type != "X509 CRL" {
			continue
		}
		parsedAny = true
		list, err := x509.ParseRevocationList(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse client CRL: %w", err)
		}
		if err := verifyRevocationList(list, issuers); err != nil {
			return nil, err
		}
		for _, entry := range list.RevokedCertificateEntries {
			revoked[serialKey(entry.SerialNumber)] = struct{}{}
		}
	}
	if !parsedAny {
		return nil, fmt.Errorf("client CRL file does not contain a valid PEM CRL")
	}
	return revoked, nil
}

func parseCertificatesFromPEM(caPEM []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for len(caPEM) > 0 {
		var block *pem.Block
		block, caPEM = pem.Decode(caPEM)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse client CA certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("client CA file does not contain a valid PEM certificate")
	}
	return certs, nil
}

func verifyRevocationList(list *x509.RevocationList, issuers []*x509.Certificate) error {
	for _, issuer := range issuers {
		if err := list.CheckSignatureFrom(issuer); err == nil {
			return nil
		}
	}
	return fmt.Errorf("client CRL signature is not trusted by the configured client CA")
}

type reloadableCRLVerifier struct {
	mu      sync.RWMutex
	crlFile string
	caPEM   []byte
	revoked map[string]struct{}
	modTime time.Time
	size    int64
}

func newReloadableCRLVerifier(crlFile string, caPEM []byte) (*reloadableCRLVerifier, error) {
	verifier := &reloadableCRLVerifier{crlFile: crlFile, caPEM: append([]byte(nil), caPEM...)}
	if err := verifier.reloadIfChanged(); err != nil {
		return nil, err
	}
	return verifier, nil
}

func (v *reloadableCRLVerifier) Verify(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	if err := v.reloadIfChanged(); err != nil {
		return err
	}
	if len(rawCerts) == 0 {
		return nil
	}
	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("parse client certificate: %w", err)
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	if _, ok := v.revoked[serialKey(cert.SerialNumber)]; ok {
		return ErrRevokedClientCertificate
	}
	return nil
}

func (v *reloadableCRLVerifier) reloadIfChanged() error {
	stat, err := os.Stat(v.crlFile)
	if err != nil {
		return fmt.Errorf("stat client CRL: %w", err)
	}
	v.mu.RLock()
	unchanged := !v.modTime.IsZero() && stat.ModTime().Equal(v.modTime) && stat.Size() == v.size
	v.mu.RUnlock()
	if unchanged {
		return nil
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if !v.modTime.IsZero() && stat.ModTime().Equal(v.modTime) && stat.Size() == v.size {
		return nil
	}
	revoked, err := LoadRevokedClientSerials(v.crlFile, v.caPEM)
	if err != nil {
		return err
	}
	v.revoked = revoked
	v.modTime = stat.ModTime()
	v.size = stat.Size()
	return nil
}

func revokedClientVerifier(revoked map[string]struct{}) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return nil
		}
		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("parse client certificate: %w", err)
		}
		if _, ok := revoked[serialKey(cert.SerialNumber)]; ok {
			return ErrRevokedClientCertificate
		}
		return nil
	}
}

func serialKey(serial *big.Int) string {
	if serial == nil {
		return ""
	}
	return serial.Text(16)
}
