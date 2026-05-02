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

type Config struct {
	ServerURL string
	CertFile  string
	KeyFile   string
	CAFile    string
}

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
	SecretID            string
	Status              string
	ClientID            string
	RequestedByClientID string
}

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

func (c *Client) Me() (model.Client, error) {
	var response model.Client
	return response, c.doJSON(http.MethodGet, "/v1/me", nil, &response)
}

func (c *Client) ListClients() ([]model.Client, error) {
	return c.ListClientsFiltered(ClientListFilters{})
}

func (c *Client) ListClientsWithLimit(limit int) ([]model.Client, error) {
	return c.ListClientsFiltered(ClientListFilters{Limit: limit})
}

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

func (c *Client) GetClient(clientID string) (model.Client, error) {
	var response model.Client
	return response, c.doJSON(http.MethodGet, "/v1/clients/"+pathEscape(clientID), nil, &response)
}

func (c *Client) CreateClient(req model.CreateClientRequest) error {
	return c.doJSON(http.MethodPost, "/v1/clients", req, nil)
}

func (c *Client) RevokeClient(req model.RevokeClientRequest) error {
	return c.doJSON(http.MethodPost, "/v1/clients/revoke", req, nil)
}

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

func (c *Client) ExportAuditEvents(filters AuditEventFilters) ([]byte, error) {
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
	path := "/v1/audit-events/export"
	if encoded := query.Encode(); encoded != "" {
		path += "?" + encoded
	}
	var response bytes.Buffer
	if err := c.doRaw(http.MethodGet, path, nil, &response); err != nil {
		return nil, err
	}
	return response.Bytes(), nil
}

func (c *Client) ListAccessGrantRequests(filters AccessGrantRequestFilters) ([]model.AccessGrantMetadata, error) {
	if err := validateAccessGrantRequestFilters(filters); err != nil {
		return nil, err
	}
	query := url.Values{}
	if filters.Limit > 0 {
		query.Set("limit", fmt.Sprintf("%d", filters.Limit))
	}
	addQueryFilter(query, "secret_id", filters.SecretID)
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

func (c *Client) CreateSecret(req model.CreateSecretRequest) (model.SecretVersionRef, error) {
	var ref model.SecretVersionRef
	return ref, c.doJSON(http.MethodPost, "/v1/secrets", req, &ref)
}

func (c *Client) ListSecrets() ([]model.SecretMetadata, error) {
	return c.ListSecretsWithLimit(0)
}

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

func (c *Client) GetSecret(secretID string) (model.SecretReadResponse, error) {
	var response model.SecretReadResponse
	return response, c.doJSON(http.MethodGet, "/v1/secrets/"+pathEscape(secretID), nil, &response)
}

func (c *Client) ListSecretVersions(secretID string) ([]model.SecretVersionMetadata, error) {
	return c.ListSecretVersionsWithLimit(secretID, 0)
}

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

func (c *Client) ListSecretAccess(secretID string) ([]model.SecretAccessMetadata, error) {
	return c.ListSecretAccessWithLimit(secretID, 0)
}

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

func (c *Client) Status() (model.OperationalStatus, error) {
	var response model.OperationalStatus
	return response, c.doJSON(http.MethodGet, "/v1/status", nil, &response)
}

func (c *Client) ShareSecret(secretID string, req model.ShareSecretRequest) error {
	return c.doJSON(http.MethodPost, "/v1/secrets/"+pathEscape(secretID)+"/share", req, nil)
}

func (c *Client) RequestAccessGrant(secretID string, req model.AccessGrantRequest) (model.AccessGrantRef, error) {
	var ref model.AccessGrantRef
	return ref, c.doJSON(http.MethodPost, "/v1/secrets/"+pathEscape(secretID)+"/access-requests", req, &ref)
}

func (c *Client) ActivateAccessGrant(secretID, targetClientID string, req model.ActivateAccessRequest) error {
	path := "/v1/secrets/" + pathEscape(secretID) + "/access/" + pathEscape(targetClientID) + "/activate"
	return c.doJSON(http.MethodPost, path, req, nil)
}

func (c *Client) RevokeAccess(secretID, targetClientID string) error {
	path := "/v1/secrets/" + pathEscape(secretID) + "/access/" + pathEscape(targetClientID)
	return c.doJSON(http.MethodDelete, path, nil, nil)
}

func (c *Client) CreateSecretVersion(secretID string, req model.CreateSecretVersionRequest) (model.SecretVersionRef, error) {
	var ref model.SecretVersionRef
	return ref, c.doJSON(http.MethodPost, "/v1/secrets/"+pathEscape(secretID)+"/versions", req, &ref)
}

func (c *Client) DeleteSecret(secretID string) error {
	return c.doJSON(http.MethodDelete, "/v1/secrets/"+pathEscape(secretID), nil, nil)
}

func (c *Client) doRaw(method, path string, payload any, out io.Writer) error {
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
	_, err = io.Copy(out, res.Body)
	return err
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
	if filters.SecretID != "" && !model.ValidUUIDID(filters.SecretID) {
		return fmt.Errorf("secret id filter is invalid")
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
