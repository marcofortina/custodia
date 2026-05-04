package client

import (
	"fmt"
	"net/http"
	"net/url"
)

func (c *Client) CurrentClientInfo() (ClientInfo, error) {
	var response ClientInfo
	return response, c.doJSON(http.MethodGet, "/v1/me", nil, &response)
}

func (c *Client) ListClientInfos(filters ClientListFilters) ([]ClientInfo, error) {
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
		Clients []ClientInfo `json:"clients"`
	}
	err := c.doJSON(http.MethodGet, path, nil, &response)
	return response.Clients, err
}

func (c *Client) GetClientInfo(clientID string) (ClientInfo, error) {
	var response ClientInfo
	return response, c.doJSON(http.MethodGet, "/v1/clients/"+pathEscape(clientID), nil, &response)
}

func (c *Client) CreateClientInfo(req CreateClientPayload) error {
	return c.doJSON(http.MethodPost, "/v1/clients", req, nil)
}

func (c *Client) RevokeClientInfo(req RevokeClientPayload) error {
	return c.doJSON(http.MethodPost, "/v1/clients/revoke", req, nil)
}

func (c *Client) CreateSecretPayload(req CreateSecretPayload) (SecretVersionRef, error) {
	var ref SecretVersionRef
	return ref, c.doJSON(http.MethodPost, "/v1/secrets", req, &ref)
}

func (c *Client) GetSecretPayload(secretID string) (SecretReadResponse, error) {
	var response SecretReadResponse
	return response, c.doJSON(http.MethodGet, "/v1/secrets/"+pathEscape(secretID), nil, &response)
}

func (c *Client) ListSecretMetadataPublic(limit int) ([]SecretMetadata, error) {
	return c.ListSecretMetadata(limit)
}

func (c *Client) ListSecretMetadata(limit int) ([]SecretMetadata, error) {
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
		Secrets []SecretMetadata `json:"secrets"`
	}
	err := c.doJSON(http.MethodGet, path, nil, &response)
	return response.Secrets, err
}

func (c *Client) ListSecretVersionMetadata(secretID string, limit int) ([]SecretVersionMetadata, error) {
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
		Versions []SecretVersionMetadata `json:"versions"`
	}
	err := c.doJSON(http.MethodGet, path, nil, &response)
	return response.Versions, err
}

func (c *Client) ListSecretAccessMetadata(secretID string, limit int) ([]SecretAccessMetadata, error) {
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
		Access []SecretAccessMetadata `json:"access"`
	}
	err := c.doJSON(http.MethodGet, path, nil, &response)
	return response.Access, err
}

func (c *Client) ShareSecretPayload(secretID string, req ShareSecretPayload) error {
	return c.doJSON(http.MethodPost, "/v1/secrets/"+pathEscape(secretID)+"/share", req, nil)
}

func (c *Client) CreateAccessGrant(secretID string, req AccessGrantPayload) (AccessGrantRef, error) {
	var ref AccessGrantRef
	return ref, c.doJSON(http.MethodPost, "/v1/secrets/"+pathEscape(secretID)+"/access-requests", req, &ref)
}

func (c *Client) ActivateAccessGrantPayload(secretID, targetClientID string, req ActivateAccessPayload) error {
	return c.doJSON(http.MethodPost, "/v1/secrets/"+pathEscape(secretID)+"/access-requests/"+pathEscape(targetClientID)+"/activate", req, nil)
}

func (c *Client) CreateSecretVersionPayload(secretID string, req CreateSecretVersionPayload) (SecretVersionRef, error) {
	var ref SecretVersionRef
	return ref, c.doJSON(http.MethodPost, "/v1/secrets/"+pathEscape(secretID)+"/versions", req, &ref)
}

func (c *Client) ListAccessGrantMetadata(filters AccessGrantRequestFilters) ([]AccessGrantMetadata, error) {
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
		AccessRequests []AccessGrantMetadata `json:"access_requests"`
	}
	err := c.doJSON(http.MethodGet, path, nil, &response)
	return response.AccessRequests, err
}
