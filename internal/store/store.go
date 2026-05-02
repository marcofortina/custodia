package store

import (
	"context"

	"custodia/internal/model"
)

type Store interface {
	Health(ctx context.Context) error
	CreateClient(ctx context.Context, client model.Client) error
	GetActiveClientBySubject(ctx context.Context, mtlsSubject string) (model.Client, error)
	ListClients(ctx context.Context) ([]model.Client, error)
	RevokeClient(ctx context.Context, clientID string) error
	CreateSecret(ctx context.Context, actorClientID string, req model.CreateSecretRequest) (model.SecretVersionRef, error)
	ListSecrets(ctx context.Context, actorClientID string) ([]model.SecretMetadata, error)
	GetSecret(ctx context.Context, actorClientID, secretID string) (model.SecretReadResponse, error)
	ListSecretVersions(ctx context.Context, actorClientID, secretID string) ([]model.SecretVersionMetadata, error)
	ListSecretAccess(ctx context.Context, actorClientID, secretID string) ([]model.SecretAccessMetadata, error)
	DeleteSecret(ctx context.Context, actorClientID, secretID string) error
	ShareSecret(ctx context.Context, actorClientID, secretID string, req model.ShareSecretRequest) error
	RequestAccessGrant(ctx context.Context, actorClientID, secretID string, req model.AccessGrantRequest) (model.AccessGrantRef, error)
	ActivateAccessGrant(ctx context.Context, actorClientID, secretID, targetClientID string, req model.ActivateAccessRequest) error
	RevokeAccess(ctx context.Context, actorClientID, secretID, targetClientID string) error
	CreateSecretVersion(ctx context.Context, actorClientID, secretID string, req model.CreateSecretVersionRequest) (model.SecretVersionRef, error)
	AppendAudit(ctx context.Context, event model.AuditEvent) error
	ListAuditEvents(ctx context.Context, limit int) ([]model.AuditEvent, error)
}
