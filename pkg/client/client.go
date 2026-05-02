package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
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

func (c *Client) CreateSecret(req model.CreateSecretRequest) (model.SecretVersionRef, error) {
	var ref model.SecretVersionRef
	return ref, c.doJSON(http.MethodPost, "/v1/secrets", req, &ref)
}

func (c *Client) ListSecrets() ([]model.SecretMetadata, error) {
	var response struct {
		Secrets []model.SecretMetadata `json:"secrets"`
	}
	err := c.doJSON(http.MethodGet, "/v1/secrets", nil, &response)
	return response.Secrets, err
}

func (c *Client) GetSecret(secretID string) (model.SecretReadResponse, error) {
	var response model.SecretReadResponse
	return response, c.doJSON(http.MethodGet, "/v1/secrets/"+pathEscape(secretID), nil, &response)
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
