package client

import "custodia/internal/model"

func toModelEnvelopes(envelopes []RecipientEnvelope) []model.RecipientEnvelope {
	converted := make([]model.RecipientEnvelope, 0, len(envelopes))
	for _, envelope := range envelopes {
		converted = append(converted, model.RecipientEnvelope{ClientID: envelope.ClientID, Envelope: envelope.Envelope})
	}
	return converted
}

func fromModelClient(value model.Client) ClientInfo {
	return ClientInfo(value)
}

func fromModelSecretRef(value model.SecretVersionRef) SecretVersionRef {
	return SecretVersionRef(value)
}

func fromModelAccessGrantRef(value model.AccessGrantRef) AccessGrantRef {
	return AccessGrantRef(value)
}

func fromModelSecretMetadata(value model.SecretMetadata) SecretMetadata {
	return SecretMetadata(value)
}

func fromModelSecretVersionMetadata(value model.SecretVersionMetadata) SecretVersionMetadata {
	return SecretVersionMetadata(value)
}

func fromModelSecretAccessMetadata(value model.SecretAccessMetadata) SecretAccessMetadata {
	return SecretAccessMetadata(value)
}

func fromModelAccessGrantMetadata(value model.AccessGrantMetadata) AccessGrantMetadata {
	return AccessGrantMetadata(value)
}

func fromModelSecretReadResponse(value model.SecretReadResponse) SecretReadResponse {
	return SecretReadResponse(value)
}
