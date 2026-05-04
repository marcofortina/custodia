package client

import (
	"errors"
	"fmt"

	"custodia/internal/clientcrypto"
)

func mapClientCryptoError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, clientcrypto.ErrUnsupportedVersion):
		return ErrUnsupportedCryptoVersion
	case errors.Is(err, clientcrypto.ErrUnsupportedContentCipher):
		return ErrUnsupportedContentCipher
	case errors.Is(err, clientcrypto.ErrUnsupportedEnvelopeScheme):
		return ErrUnsupportedEnvelopeScheme
	case errors.Is(err, clientcrypto.ErrMalformedMetadata), errors.Is(err, clientcrypto.ErrMalformedAAD), errors.Is(err, clientcrypto.ErrMalformedVector):
		return ErrMalformedCryptoMetadata
	case errors.Is(err, clientcrypto.ErrContentAuthFailed):
		return ErrCiphertextAuthFailed
	case errors.Is(err, clientcrypto.ErrEnvelopeAuthFailed):
		return ErrWrongRecipient
	default:
		return fmt.Errorf("%w: %v", ErrMalformedCryptoMetadata, err)
	}
}
