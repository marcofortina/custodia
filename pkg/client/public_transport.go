package client

import "custodia/internal/model"

func (c *Client) CurrentClientInfo() (ClientInfo, error) {
	value, err := c.Me()
	if err != nil {
		return ClientInfo{}, err
	}
	return fromModelClient(value), nil
}

func (c *Client) ListClientInfos(filters ClientListFilters) ([]ClientInfo, error) {
	values, err := c.ListClientsFiltered(filters)
	if err != nil {
		return nil, err
	}
	converted := make([]ClientInfo, 0, len(values))
	for _, value := range values {
		converted = append(converted, fromModelClient(value))
	}
	return converted, nil
}

func (c *Client) GetClientInfo(clientID string) (ClientInfo, error) {
	value, err := c.GetClient(clientID)
	if err != nil {
		return ClientInfo{}, err
	}
	return fromModelClient(value), nil
}

func (c *Client) CreateClientInfo(req CreateClientPayload) error {
	return c.CreateClient(model.CreateClientRequest{ClientID: req.ClientID, MTLSSubject: req.MTLSSubject})
}

func (c *Client) RevokeClientInfo(req RevokeClientPayload) error {
	return c.RevokeClient(model.RevokeClientRequest{ClientID: req.ClientID, Reason: req.Reason})
}

func (c *Client) CreateSecretPayload(req CreateSecretPayload) (SecretVersionRef, error) {
	ref, err := c.CreateSecret(model.CreateSecretRequest{
		Name:           req.Name,
		Ciphertext:     req.Ciphertext,
		CryptoMetadata: req.CryptoMetadata,
		Envelopes:      toModelEnvelopes(req.Envelopes),
		Permissions:    req.Permissions,
		ExpiresAt:      req.ExpiresAt,
	})
	if err != nil {
		return SecretVersionRef{}, err
	}
	return fromModelSecretRef(ref), nil
}

func (c *Client) GetSecretPayload(secretID string) (SecretReadResponse, error) {
	value, err := c.GetSecret(secretID)
	if err != nil {
		return SecretReadResponse{}, err
	}
	return fromModelSecretReadResponse(value), nil
}

func (c *Client) ListSecretMetadataPublic(limit int) ([]SecretMetadata, error) {
	values, err := c.ListSecretsWithLimit(limit)
	if err != nil {
		return nil, err
	}
	converted := make([]SecretMetadata, 0, len(values))
	for _, value := range values {
		converted = append(converted, fromModelSecretMetadata(value))
	}
	return converted, nil
}

func (c *Client) ListSecretVersionMetadata(secretID string, limit int) ([]SecretVersionMetadata, error) {
	values, err := c.ListSecretVersionsWithLimit(secretID, limit)
	if err != nil {
		return nil, err
	}
	converted := make([]SecretVersionMetadata, 0, len(values))
	for _, value := range values {
		converted = append(converted, fromModelSecretVersionMetadata(value))
	}
	return converted, nil
}

func (c *Client) ListSecretAccessMetadata(secretID string, limit int) ([]SecretAccessMetadata, error) {
	values, err := c.ListSecretAccessWithLimit(secretID, limit)
	if err != nil {
		return nil, err
	}
	converted := make([]SecretAccessMetadata, 0, len(values))
	for _, value := range values {
		converted = append(converted, fromModelSecretAccessMetadata(value))
	}
	return converted, nil
}

func (c *Client) ShareSecretPayload(secretID string, req ShareSecretPayload) error {
	return c.ShareSecret(secretID, model.ShareSecretRequest{
		VersionID:      req.VersionID,
		TargetClientID: req.TargetClientID,
		Envelope:       req.Envelope,
		Permissions:    req.Permissions,
		ExpiresAt:      req.ExpiresAt,
	})
}

func (c *Client) CreateAccessGrant(secretID string, req AccessGrantPayload) (AccessGrantRef, error) {
	ref, err := c.RequestAccessGrant(secretID, model.AccessGrantRequest{
		VersionID:      req.VersionID,
		TargetClientID: req.TargetClientID,
		Permissions:    req.Permissions,
		ExpiresAt:      req.ExpiresAt,
	})
	if err != nil {
		return AccessGrantRef{}, err
	}
	return fromModelAccessGrantRef(ref), nil
}

func (c *Client) ActivateAccessGrantPayload(secretID, targetClientID string, req ActivateAccessPayload) error {
	return c.ActivateAccessGrant(secretID, targetClientID, model.ActivateAccessRequest{Envelope: req.Envelope})
}

func (c *Client) CreateSecretVersionPayload(secretID string, req CreateSecretVersionPayload) (SecretVersionRef, error) {
	ref, err := c.CreateSecretVersion(secretID, model.CreateSecretVersionRequest{
		Ciphertext:     req.Ciphertext,
		CryptoMetadata: req.CryptoMetadata,
		Envelopes:      toModelEnvelopes(req.Envelopes),
		Permissions:    req.Permissions,
		ExpiresAt:      req.ExpiresAt,
	})
	if err != nil {
		return SecretVersionRef{}, err
	}
	return fromModelSecretRef(ref), nil
}

func (c *Client) ListAccessGrantMetadata(filters AccessGrantRequestFilters) ([]AccessGrantMetadata, error) {
	values, err := c.ListAccessGrantRequests(filters)
	if err != nil {
		return nil, err
	}
	converted := make([]AccessGrantMetadata, 0, len(values))
	for _, value := range values {
		converted = append(converted, fromModelAccessGrantMetadata(value))
	}
	return converted, nil
}
