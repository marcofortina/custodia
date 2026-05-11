// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"custodia/internal/model"
	"custodia/internal/mtls"
)

// Config describes the public transport client settings.
//
// The client always uses mutual TLS; there is no bearer-token fallback because
// Custodia identifies API callers from the client certificate subject.
type Config struct {
	ServerURL string
	CertFile  string
	KeyFile   string
	CAFile    string
}

// Client is the public REST/mTLS transport SDK.
//
// Transport methods forward ciphertext, envelopes and crypto_metadata as opaque
// JSON values. High-level encryption is layered separately by CryptoClient.
type Client struct {
	baseURL string
	http    *http.Client
}

type ClientListFilters struct {
	Limit  int
	Active *bool
}

type AuditEventFilters struct {
	Limit         int
	Outcome       string
	Action        string
	ActorClientID string
	ResourceType  string
	ResourceID    string
}

type AccessGrantRequestFilters struct {
	Limit               int
	Namespace           string
	Key                 string
	Status              string
	ClientID            string
	RequestedByClientID string
}

// New builds a transport client with TLS 1.3 mTLS configuration.
//
// The HTTP timeout is intentionally finite so SDK callers do not hang forever
// on network partitions or unavailable load balancers.
func New(cfg Config) (*Client, error) {
	tlsConfig, err := mtls.ClientTLSConfig(cfg.CertFile, cfg.KeyFile, cfg.CAFile)
	if err != nil {
		return nil, err
	}
	return &Client{
		baseURL: cfg.ServerURL,
		http: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
		},
	}, nil
}

// Me is a monorepo internal-model helper that returns internal model types. External consumers should use CurrentClientInfo.
func (c *Client) Me() (model.Client, error) {
	var response model.Client
	return response, c.doJSON(http.MethodGet, "/v1/me", nil, &response)
}

// ListClients is a monorepo internal-model helper that returns internal model types. External consumers should use ListClientInfos.
func (c *Client) ListClients() ([]model.Client, error) {
	return c.ListClientsFiltered(ClientListFilters{})
}

// ListClientsWithLimit is a monorepo internal-model helper that returns internal model types. External consumers should use ListClientInfos.
func (c *Client) ListClientsWithLimit(limit int) ([]model.Client, error) {
	return c.ListClientsFiltered(ClientListFilters{Limit: limit})
}

// ListClientsFiltered is a monorepo internal-model helper that returns internal model types. External consumers should use ListClientInfos.
func (c *Client) ListClientsFiltered(filters ClientListFilters) ([]model.Client, error) {
	if err := validateOptionalLimit(filters.Limit); err != nil {
		return nil, err
	}
	query := url.Values{}
	if filters.Limit > 0 {
		query.Set("limit", fmt.Sprintf("%d", filters.Limit))
	}
	if filters.Active != nil {
		query.Set("active", fmt.Sprintf("%t", *filters.Active))
	}
	path := "/v1/clients"
	if encoded := query.Encode(); encoded != "" {
		path += "?" + encoded
	}
	var response struct {
		Clients []model.Client `json:"clients"`
	}
	err := c.doJSON(http.MethodGet, path, nil, &response)
	return response.Clients, err
}

// GetClient is a monorepo internal-model helper that returns internal model types. External consumers should use GetClientInfo.
func (c *Client) GetClient(clientID string) (model.Client, error) {
	var response model.Client
	return response, c.doJSON(http.MethodGet, "/v1/clients/"+pathEscape(clientID), nil, &response)
}

// CreateClient is a monorepo internal-model helper that accepts internal model types. External consumers should use CreateClientInfo.
func (c *Client) CreateClient(req model.CreateClientRequest) error {
	return c.doJSON(http.MethodPost, "/v1/clients", req, nil)
}

// RevokeClient is a monorepo internal-model helper that accepts internal model types. External consumers should use RevokeClientInfo.
func (c *Client) RevokeClient(req model.RevokeClientRequest) error {
	return c.doJSON(http.MethodPost, "/v1/clients/revoke", req, nil)
}

// ListAuditEvents is a monorepo internal-model helper that returns internal model types. External consumers should use ListAuditEventMetadata.
func (c *Client) ListAuditEvents(filters AuditEventFilters) ([]model.AuditEvent, error) {
	if err := validateAuditEventFilters(filters); err != nil {
		return nil, err
	}
	query := url.Values{}
	if filters.Limit > 0 {
		query.Set("limit", fmt.Sprintf("%d", filters.Limit))
	}
	addQueryFilter(query, "outcome", filters.Outcome)
	addQueryFilter(query, "action", filters.Action)
	addQueryFilter(query, "actor_client_id", filters.ActorClientID)
	addQueryFilter(query, "resource_type", filters.ResourceType)
	addQueryFilter(query, "resource_id", filters.ResourceID)
	path := "/v1/audit-events"
	if encoded := query.Encode(); encoded != "" {
		path += "?" + encoded
	}
	var response struct {
		AuditEvents []model.AuditEvent `json:"audit_events"`
	}
	err := c.doJSON(http.MethodGet, path, nil, &response)
	return response.AuditEvents, err
}

// ExportAuditEvents returns only the audit JSONL body. External consumers should use ExportAuditEventArtifact when they need response metadata.
func (c *Client) ExportAuditEvents(filters AuditEventFilters) ([]byte, error) {
	artifact, err := c.ExportAuditEventsWithMetadata(filters)
	if err != nil {
		return nil, err
	}
	return artifact.Body, nil
}

// ExportAuditEventsWithMetadata returns the audit JSONL body plus export metadata. ExportAuditEventArtifact is the preferred public helper.
func (c *Client) ExportAuditEventsWithMetadata(filters AuditEventFilters) (AuditExportArtifact, error) {
	if err := validateAuditEventFilters(filters); err != nil {
		return AuditExportArtifact{}, err
	}
	query := url.Values{}
	if filters.Limit > 0 {
		query.Set("limit", fmt.Sprintf("%d", filters.Limit))
	}
	addQueryFilter(query, "outcome", filters.Outcome)
	addQueryFilter(query, "action", filters.Action)
	addQueryFilter(query, "actor_client_id", filters.ActorClientID)
	addQueryFilter(query, "resource_type", filters.ResourceType)
	addQueryFilter(query, "resource_id", filters.ResourceID)
	path := "/v1/audit-events/export"
	if encoded := query.Encode(); encoded != "" {
		path += "?" + encoded
	}
	var response bytes.Buffer
	headers, err := c.doRawWithHeaders(http.MethodGet, path, nil, &response)
	if err != nil {
		return AuditExportArtifact{}, err
	}
	return AuditExportArtifact{
		Body:       response.Bytes(),
		SHA256:     headers.Get("X-Custodia-Audit-Export-SHA256"),
		EventCount: headers.Get("X-Custodia-Audit-Export-Events"),
	}, nil
}

// ListAccessGrantRequests is a monorepo internal-model helper that returns internal model types. External consumers should use ListAccessGrantMetadata.
func (c *Client) ListAccessGrantRequests(filters AccessGrantRequestFilters) ([]model.AccessGrantMetadata, error) {
	if err := validateAccessGrantRequestFilters(filters); err != nil {
		return nil, err
	}
	query := url.Values{}
	if filters.Limit > 0 {
		query.Set("limit", fmt.Sprintf("%d", filters.Limit))
	}
	addQueryFilter(query, "namespace", filters.Namespace)
	addQueryFilter(query, "key", filters.Key)
	addQueryFilter(query, "status", filters.Status)
	addQueryFilter(query, "client_id", filters.ClientID)
	addQueryFilter(query, "requested_by_client_id", filters.RequestedByClientID)
	path := "/v1/access-requests"
	if encoded := query.Encode(); encoded != "" {
		path += "?" + encoded
	}
	var response struct {
		AccessRequests []model.AccessGrantMetadata `json:"access_requests"`
	}
	err := c.doJSON(http.MethodGet, path, nil, &response)
	return response.AccessRequests, err
}

// CreateSecret is a monorepo internal-model helper that accepts internal model types. External consumers should use CreateSecretPayload.
func (c *Client) CreateSecret(req model.CreateSecretRequest) (model.SecretVersionRef, error) {
	var ref model.SecretVersionRef
	return ref, c.doJSON(http.MethodPost, "/v1/secrets", req, &ref)
}

// ListSecrets is a monorepo internal-model helper that returns internal model types. External consumers should use ListSecretMetadata.
func (c *Client) ListSecrets() ([]model.SecretMetadata, error) {
	return c.ListSecretsWithLimit(0)
}

// ListSecretsWithLimit is a monorepo internal-model helper that returns internal model types. External consumers should use ListSecretMetadata.
func (c *Client) ListSecretsWithLimit(limit int) ([]model.SecretMetadata, error) {
	if err := validateOptionalLimit(limit); err != nil {
		return nil, err
	}
	path := "/v1/secrets"
	if limit > 0 {
		query := url.Values{}
		query.Set("limit", fmt.Sprintf("%d", limit))
		path += "?" + query.Encode()
	}
	var response struct {
		Secrets []model.SecretMetadata `json:"secrets"`
	}
	err := c.doJSON(http.MethodGet, path, nil, &response)
	return response.Secrets, err
}

// GetSecret is a monorepo internal-model helper that returns internal model types. External consumers should use GetSecretPayload.
func (c *Client) GetSecret(secretID string) (model.SecretReadResponse, error) {
	var response model.SecretReadResponse
	return response, c.doJSON(http.MethodGet, "/v1/secrets/"+pathEscape(secretID), nil, &response)
}

// ListSecretVersions is a monorepo internal-model helper that returns internal model types. External consumers should use ListSecretVersionMetadata.
func (c *Client) ListSecretVersions(secretID string) ([]model.SecretVersionMetadata, error) {
	return c.ListSecretVersionsWithLimit(secretID, 0)
}

// ListSecretVersionsWithLimit is a monorepo internal-model helper that returns internal model types. External consumers should use ListSecretVersionMetadata.
func (c *Client) ListSecretVersionsWithLimit(secretID string, limit int) ([]model.SecretVersionMetadata, error) {
	if err := validateOptionalLimit(limit); err != nil {
		return nil, err
	}
	path := "/v1/secrets/" + pathEscape(secretID) + "/versions"
	if limit > 0 {
		query := url.Values{}
		query.Set("limit", fmt.Sprintf("%d", limit))
		path += "?" + query.Encode()
	}
	var response struct {
		Versions []model.SecretVersionMetadata `json:"versions"`
	}
	err := c.doJSON(http.MethodGet, path, nil, &response)
	return response.Versions, err
}

// ListSecretAccess is a monorepo internal-model helper that returns internal model types. External consumers should use ListSecretAccessMetadata.
func (c *Client) ListSecretAccess(secretID string) ([]model.SecretAccessMetadata, error) {
	return c.ListSecretAccessWithLimit(secretID, 0)
}

// ListSecretAccessWithLimit is a monorepo internal-model helper that returns internal model types. External consumers should use ListSecretAccessMetadata.
func (c *Client) ListSecretAccessWithLimit(secretID string, limit int) ([]model.SecretAccessMetadata, error) {
	if err := validateOptionalLimit(limit); err != nil {
		return nil, err
	}
	path := "/v1/secrets/" + pathEscape(secretID) + "/access"
	if limit > 0 {
		query := url.Values{}
		query.Set("limit", fmt.Sprintf("%d", limit))
		path += "?" + query.Encode()
	}
	var response struct {
		Access []model.SecretAccessMetadata `json:"access"`
	}
	err := c.doJSON(http.MethodGet, path, nil, &response)
	return response.Access, err
}

// Status is a monorepo internal-model helper that returns internal model types. External consumers should use StatusInfo.
func (c *Client) Status() (model.OperationalStatus, error) {
	var response model.OperationalStatus
	return response, c.doJSON(http.MethodGet, "/v1/status", nil, &response)
}

// Version is a monorepo internal-model helper that returns internal model types. External consumers should use VersionInfo.
func (c *Client) Version() (model.BuildInfo, error) {
	var response model.BuildInfo
	return response, c.doJSON(http.MethodGet, "/v1/version", nil, &response)
}

// Diagnostics is a monorepo internal-model helper that returns internal model types. External consumers should use DiagnosticsInfo.
func (c *Client) Diagnostics() (model.RuntimeDiagnostics, error) {
	var response model.RuntimeDiagnostics
	return response, c.doJSON(http.MethodGet, "/v1/diagnostics", nil, &response)
}

// RevocationStatus is a monorepo internal-model helper that returns internal model types. External consumers should use RevocationStatusInfo.
func (c *Client) RevocationStatus() (model.RevocationStatus, error) {
	var response model.RevocationStatus
	return response, c.doJSON(http.MethodGet, "/v1/revocation/status", nil, &response)
}

// RevocationSerialStatus returns revocation metadata for a certificate serial. RevocationSerialStatusInfo is the preferred public helper.
func (c *Client) RevocationSerialStatus(serialHex string) (RevocationSerialStatus, error) {
	var response RevocationSerialStatus
	path := "/v1/revocation/serial?serial_hex=" + url.QueryEscape(strings.TrimSpace(serialHex))
	return response, c.doJSON(http.MethodGet, path, nil, &response)
}

// ShareSecret is a monorepo internal-model helper that accepts internal model types. External consumers should use ShareSecretPayload.
func (c *Client) ShareSecret(secretID string, req model.ShareSecretRequest) error {
	return c.doJSON(http.MethodPost, "/v1/secrets/"+pathEscape(secretID)+"/share", req, nil)
}

// RequestAccessGrant is a monorepo internal-model helper that accepts internal model types. External consumers should use CreateAccessGrant.
func (c *Client) RequestAccessGrant(secretID string, req model.AccessGrantRequest) (model.AccessGrantRef, error) {
	var ref model.AccessGrantRef
	return ref, c.doJSON(http.MethodPost, "/v1/secrets/"+pathEscape(secretID)+"/access-requests", req, &ref)
}

// ActivateAccessGrant is a monorepo internal-model helper that accepts internal model types. External consumers should use ActivateAccessGrantPayload.
func (c *Client) ActivateAccessGrant(secretID, targetClientID string, req model.ActivateAccessRequest) error {
	path := "/v1/secrets/" + pathEscape(secretID) + "/access/" + pathEscape(targetClientID) + "/activate"
	return c.doJSON(http.MethodPost, path, req, nil)
}

func (c *Client) RevokeAccess(secretID, targetClientID string) error {
	path := "/v1/secrets/" + pathEscape(secretID) + "/access/" + pathEscape(targetClientID)
	return c.doJSON(http.MethodDelete, path, nil, nil)
}

// CreateSecretVersion is a monorepo internal-model helper that accepts internal model types. External consumers should use CreateSecretVersionPayload.
func (c *Client) CreateSecretVersion(secretID string, req model.CreateSecretVersionRequest) (model.SecretVersionRef, error) {
	var ref model.SecretVersionRef
	return ref, c.doJSON(http.MethodPost, "/v1/secrets/"+pathEscape(secretID)+"/versions", req, &ref)
}

func (c *Client) DeleteSecret(secretID string) error {
	return c.DeleteSecretWithCascade(secretID, false)
}

func (c *Client) DeleteSecretWithCascade(secretID string, cascade bool) error {
	path := "/v1/secrets/" + pathEscape(secretID)
	if cascade {
		query := url.Values{}
		query.Set("cascade", "true")
		path += "?" + query.Encode()
	}
	return c.doJSON(http.MethodDelete, path, nil, nil)
}

func (c *Client) DeleteSecretByKey(namespace, key string, cascade bool) error {
	path, err := secretByKeyPath("/v1/secrets/by-key", namespace, key, cascade)
	if err != nil {
		return err
	}
	return c.doJSON(http.MethodDelete, path, nil, nil)
}

func (c *Client) doRaw(method, path string, payload any, out io.Writer) error {
	_, err := c.doRawWithHeaders(method, path, payload, out)
	return err
}

// doRawWithHeaders is the single transport boundary for the Go SDK.
//
// It serializes only caller-provided payloads and returns typed HTTP errors
// without embedding request bodies, so ciphertext/envelopes are not leaked in
// error messages.
func (c *Client) doRawWithHeaders(method, path string, payload any, out io.Writer) (http.Header, error) {
	var body io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(encoded)
	}
	req, err := http.NewRequest(method, c.baseURL+path, body)
	if err != nil {
		return nil, err
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode > 299 {
		responseBody, _ := io.ReadAll(res.Body)
		return nil, fmt.Errorf("custodia request failed: %s: %s", res.Status, string(responseBody))
	}
	_, err = io.Copy(out, res.Body)
	if err != nil {
		return nil, err
	}
	return res.Header, nil
}

func (c *Client) doJSON(method, path string, payload any, target any) error {
	var body io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		body = bytes.NewReader(encoded)
	}
	req, err := http.NewRequest(method, c.baseURL+path, body)
	if err != nil {
		return err
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode > 299 {
		responseBody, _ := io.ReadAll(res.Body)
		return fmt.Errorf("custodia request failed: %s: %s", res.Status, string(responseBody))
	}
	if target == nil {
		_, _ = io.Copy(io.Discard, res.Body)
		return nil
	}
	return json.NewDecoder(res.Body).Decode(target)
}

func pathEscape(value string) string {
	return url.PathEscape(value)
}

func addQueryFilter(query url.Values, key string, value string) {
	if value != "" {
		query.Set(key, value)
	}
}

func validateAccessGrantRequestFilters(filters AccessGrantRequestFilters) error {
	if err := validateOptionalLimit(filters.Limit); err != nil {
		return err
	}
	if filters.Namespace != "" {
		if strings.TrimSpace(filters.Namespace) == "" || !model.ValidSecretNamespace(filters.Namespace) {
			return fmt.Errorf("secret namespace filter is invalid")
		}
	}
	if filters.Key != "" {
		if strings.TrimSpace(filters.Key) == "" || !model.ValidSecretKey(filters.Key) {
			return fmt.Errorf("secret key filter is invalid")
		}
	}
	if filters.Status != "" && !model.ValidAccessRequestStatus(filters.Status) {
		return fmt.Errorf("status filter is invalid")
	}
	if filters.ClientID != "" && !model.ValidClientID(filters.ClientID) {
		return fmt.Errorf("client id filter is invalid")
	}
	if filters.RequestedByClientID != "" && !model.ValidClientID(filters.RequestedByClientID) {
		return fmt.Errorf("requested by client id filter is invalid")
	}
	return nil
}

func validateAuditEventFilters(filters AuditEventFilters) error {
	if err := validateOptionalLimit(filters.Limit); err != nil {
		return err
	}
	if filters.Outcome != "" {
		switch strings.TrimSpace(filters.Outcome) {
		case "success", "failure", "degraded":
		default:
			return fmt.Errorf("outcome must be success, failure or degraded when set")
		}
	}
	if filters.Action != "" && !model.ValidAuditAction(filters.Action) {
		return fmt.Errorf("action filter is invalid")
	}
	if filters.ActorClientID != "" && !model.ValidClientID(filters.ActorClientID) {
		return fmt.Errorf("actor client id filter is invalid")
	}
	if filters.ResourceType != "" && !model.ValidAuditResourceType(filters.ResourceType) {
		return fmt.Errorf("resource type filter is invalid")
	}
	if filters.ResourceID != "" && !model.ValidAuditResourceID(filters.ResourceID) {
		return fmt.Errorf("resource id filter is invalid")
	}
	return nil
}

func validateOptionalLimit(limit int) error {
	if limit < 0 || limit > 500 {
		return fmt.Errorf("limit must be between 1 and 500 when set")
	}
	return nil
}
