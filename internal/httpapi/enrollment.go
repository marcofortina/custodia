// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package httpapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"custodia/internal/model"
	"custodia/internal/signing"
)

const (
	defaultEnrollmentTTL = 15 * time.Minute
	maxEnrollmentTTL     = 24 * time.Hour
	enrollmentTokenBytes = 32
)

type enrollmentToken struct {
	Hash      string
	CreatedAt time.Time
	ExpiresAt time.Time
}

func (s *Server) handleCreateClientEnrollment(w http.ResponseWriter, r *http.Request) {
	var req model.ClientEnrollmentCreateRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	serverURL := strings.TrimSpace(s.enrollmentServerURL)
	if serverURL == "" {
		s.auditFailure(r, "client.enrollment_create", "client_enrollment", "", map[string]string{"reason": "server_url_not_configured"})
		writeError(w, http.StatusServiceUnavailable, "server_url_not_configured")
		return
	}
	ttl := time.Duration(req.TTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = defaultEnrollmentTTL
	}
	if ttl > maxEnrollmentTTL {
		s.auditFailure(r, "client.enrollment_create", "client_enrollment", "", map[string]string{"reason": "invalid_ttl"})
		writeError(w, http.StatusBadRequest, "invalid_ttl")
		return
	}
	token, tokenHash, err := newEnrollmentToken()
	if err != nil {
		s.auditFailure(r, "client.enrollment_create", "client_enrollment", "", map[string]string{"reason": "token_generation_failed"})
		writeError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	now := time.Now().UTC()
	expiresAt := now.Add(ttl)
	s.enrollmentMu.Lock()
	s.enrollmentTokens[tokenHash] = enrollmentToken{Hash: tokenHash, CreatedAt: now, ExpiresAt: expiresAt}
	s.enrollmentMu.Unlock()
	s.audit(r, "client.enrollment_create", "client_enrollment", "", "success", nil)
	writeJSON(w, http.StatusCreated, model.ClientEnrollmentCreateResponse{
		ServerURL:       serverURL,
		EnrollmentToken: token,
		ExpiresAt:       expiresAt,
	})
}

func (s *Server) handleClientEnrollmentClaim(w http.ResponseWriter, r *http.Request) {
	if s.limiter != nil && s.ipRateLimit > 0 {
		allowed, err := s.limiter.Allow(r.Context(), "ip:"+remoteIP(r), s.ipRateLimit)
		if err != nil {
			s.auditFailure(r, "client.enrollment_claim", "client_enrollment", "", map[string]string{"reason": "rate_limiter_unavailable"})
			writeError(w, http.StatusServiceUnavailable, "rate_limiter_unavailable")
			return
		}
		if !allowed {
			s.auditFailure(r, "client.enrollment_claim", "client_enrollment", "", map[string]string{"reason": "ip_rate_limited"})
			writeRateLimited(w, "ip_rate_limited")
			return
		}
	}
	var req model.ClientEnrollmentClaimRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	clientID := strings.TrimSpace(req.ClientID)
	if !model.ValidClientID(clientID) || strings.TrimSpace(req.EnrollmentToken) == "" || strings.TrimSpace(req.CSRPem) == "" {
		s.auditFailure(r, "client.enrollment_claim", "client", clientID, map[string]string{"reason": "invalid_input"})
		writeError(w, http.StatusBadRequest, "invalid_input")
		return
	}
	if !s.validateEnrollmentToken(req.EnrollmentToken, time.Now().UTC()) {
		s.auditFailure(r, "client.enrollment_claim", "client", clientID, map[string]string{"reason": "invalid_or_expired_token"})
		writeError(w, http.StatusForbidden, "invalid_or_expired_token")
		return
	}
	signResponse, err := s.signEnrollmentCSR(r.Context(), clientID, []byte(req.CSRPem))
	if err != nil {
		s.auditFailure(r, "client.enrollment_claim", "client", clientID, map[string]string{"reason": "sign_failed"})
		writeError(w, http.StatusBadGateway, "sign_failed")
		return
	}
	if err := s.store.CreateClient(r.Context(), model.Client{ClientID: clientID, MTLSSubject: clientID}); err != nil {
		s.auditStoreFailure(r, "client.enrollment_claim", "client", clientID, err)
		writeMappedError(w, err)
		return
	}
	if !s.consumeEnrollmentToken(req.EnrollmentToken) {
		s.auditFailure(r, "client.enrollment_claim", "client", clientID, map[string]string{"reason": "token_consume_failed"})
		writeError(w, http.StatusForbidden, "invalid_or_expired_token")
		return
	}
	caPEM, err := os.ReadFile(strings.TrimSpace(s.signerCAFile))
	if err != nil {
		s.auditFailure(r, "client.enrollment_claim", "client", clientID, map[string]string{"reason": "ca_unavailable"})
		writeError(w, http.StatusServiceUnavailable, "ca_unavailable")
		return
	}
	s.audit(r, "client.enrollment_claim", "client", clientID, "success", nil)
	writeJSON(w, http.StatusCreated, model.ClientEnrollmentClaimResponse{
		ClientID:       clientID,
		ServerURL:      strings.TrimSpace(s.enrollmentServerURL),
		CAPEM:          string(caPEM),
		CertificatePEM: signResponse.CertificatePEM,
	})
}

func (s *Server) validateEnrollmentToken(token string, now time.Time) bool {
	hash := enrollmentTokenHash(token)
	if hash == "" {
		return false
	}
	s.enrollmentMu.Lock()
	defer s.enrollmentMu.Unlock()
	stored, ok := s.enrollmentTokens[hash]
	return ok && now.Before(stored.ExpiresAt)
}

func (s *Server) consumeEnrollmentToken(token string) bool {
	hash := enrollmentTokenHash(token)
	if hash == "" {
		return false
	}
	s.enrollmentMu.Lock()
	defer s.enrollmentMu.Unlock()
	if _, ok := s.enrollmentTokens[hash]; !ok {
		return false
	}
	delete(s.enrollmentTokens, hash)
	return true
}

func (s *Server) signEnrollmentCSR(ctx context.Context, clientID string, csrPEM []byte) (signing.SignClientCertificateResponse, error) {
	signerURL := strings.TrimRight(strings.TrimSpace(s.signerURL), "/")
	if signerURL == "" {
		return signing.SignClientCertificateResponse{}, fmt.Errorf("signer URL is not configured")
	}
	payload := signing.SignClientCertificateRequest{ClientID: clientID, CSRPem: string(csrPEM)}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return signing.SignClientCertificateResponse{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, signerURL+"/v1/certificates/sign", bytes.NewReader(encoded))
	if err != nil {
		return signing.SignClientCertificateResponse{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	client, err := s.signerHTTPClient()
	if err != nil {
		return signing.SignClientCertificateResponse{}, err
	}
	response, err := client.Do(request)
	if err != nil {
		return signing.SignClientCertificateResponse{}, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxJSONBodyBytes))
	if err != nil {
		return signing.SignClientCertificateResponse{}, err
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return signing.SignClientCertificateResponse{}, fmt.Errorf("signer returned %s: %s", response.Status, strings.TrimSpace(string(body)))
	}
	var decoded signing.SignClientCertificateResponse
	if err := json.Unmarshal(body, &decoded); err != nil {
		return signing.SignClientCertificateResponse{}, err
	}
	return decoded, nil
}

func (s *Server) signerHTTPClient() (*http.Client, error) {
	cert, err := tls.LoadX509KeyPair(strings.TrimSpace(s.signerClientCertFile), strings.TrimSpace(s.signerClientKeyFile))
	if err != nil {
		return nil, err
	}
	caPEM, err := os.ReadFile(strings.TrimSpace(s.signerCAFile))
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("invalid signer CA bundle")
	}
	return &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: roots, MinVersion: tls.VersionTLS12}}}, nil
}

func newEnrollmentToken() (string, string, error) {
	raw := make([]byte, enrollmentTokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	return token, enrollmentTokenHash(token), nil
}

func enrollmentTokenHash(token string) string {
	token = strings.TrimSpace(token)
	if token == "" {
		return ""
	}
	digest := sha256.Sum256([]byte(token))
	return hex.EncodeToString(digest[:])
}
