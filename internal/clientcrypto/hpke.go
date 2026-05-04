package clientcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	x25519PublicKeyBytes = 32
	hpkeEnvelopeInfo     = "custodia.client-crypto.v1 envelope"
)

var (
	ErrInvalidEnvelopeKey = errors.New("invalid client envelope key")
	ErrMalformedEnvelope  = errors.New("malformed client envelope")
	ErrEnvelopeAuthFailed = errors.New("client envelope authentication failed")
)

var (
	hpkeKEMID        = []byte{0x00, 0x20} // DHKEM(X25519, HKDF-SHA256)
	hpkeKDFID        = []byte{0x00, 0x01} // HKDF-SHA256
	hpkeAEADID       = []byte{0x00, 0x02} // AES-256-GCM
	hpkeKEMSuiteID   = append([]byte("KEM"), hpkeKEMID...)
	hpkeSuiteID      = append(append(append([]byte("HPKE"), hpkeKEMID...), hpkeKDFID...), hpkeAEADID...)
	hpkeVersionLabel = []byte("HPKE-v1")
)

// DeriveX25519PublicKey returns the public key for deterministic HPKE test-vector keys.
func DeriveX25519PublicKey(privateKey []byte) ([]byte, error) {
	priv, err := ecdh.X25519().NewPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidEnvelopeKey, err)
	}
	return priv.PublicKey().Bytes(), nil
}

// SealHPKEV1Envelope seals DEK material for one recipient using HPKE base-mode parameters.
func SealHPKEV1Envelope(recipientPublicKey, senderEphemeralPrivateKey, dek, aad []byte) ([]byte, error) {
	pkR, err := ecdh.X25519().NewPublicKey(recipientPublicKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidEnvelopeKey, err)
	}
	skE, err := ecdh.X25519().NewPrivateKey(senderEphemeralPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidEnvelopeKey, err)
	}
	sharedSecret, enc, err := hpkeSharedSecret(skE, pkR)
	if err != nil {
		return nil, err
	}
	sealed, err := hpkeSeal(sharedSecret, []byte(hpkeEnvelopeInfo), dek, aad)
	if err != nil {
		return nil, err
	}
	envelope := make([]byte, 0, len(enc)+len(sealed))
	envelope = append(envelope, enc...)
	envelope = append(envelope, sealed...)
	return envelope, nil
}

// OpenHPKEV1Envelope opens a deterministic HPKE test-vector envelope.
func OpenHPKEV1Envelope(recipientPrivateKey, envelope, aad []byte) ([]byte, error) {
	if len(envelope) <= x25519PublicKeyBytes+AESGCMTagBytes {
		return nil, ErrMalformedEnvelope
	}
	skR, err := ecdh.X25519().NewPrivateKey(recipientPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidEnvelopeKey, err)
	}
	pkE, err := ecdh.X25519().NewPublicKey(envelope[:x25519PublicKeyBytes])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedEnvelope, err)
	}
	sharedSecret, err := hpkeRecipientSharedSecret(skR, pkE)
	if err != nil {
		return nil, err
	}
	return hpkeOpen(sharedSecret, []byte(hpkeEnvelopeInfo), envelope[x25519PublicKeyBytes:], aad)
}

func EncodeEnvelope(envelope []byte) string {
	return base64.StdEncoding.EncodeToString(envelope)
}

func DecodeEnvelope(value string) ([]byte, error) {
	envelope, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedEnvelope, err)
	}
	return envelope, nil
}

func hpkeSharedSecret(skE *ecdh.PrivateKey, pkR *ecdh.PublicKey) ([]byte, []byte, error) {
	dh, err := skE.ECDH(pkR)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrInvalidEnvelopeKey, err)
	}
	enc := skE.PublicKey().Bytes()
	kemContext := append(append([]byte{}, enc...), pkR.Bytes()...)
	sharedSecret := hpkeKEMExtractAndExpand(dh, kemContext)
	return sharedSecret, enc, nil
}

func hpkeRecipientSharedSecret(skR *ecdh.PrivateKey, pkE *ecdh.PublicKey) ([]byte, error) {
	dh, err := skR.ECDH(pkE)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidEnvelopeKey, err)
	}
	kemContext := append(append([]byte{}, pkE.Bytes()...), skR.PublicKey().Bytes()...)
	return hpkeKEMExtractAndExpand(dh, kemContext), nil
}

func hpkeKEMExtractAndExpand(dh, kemContext []byte) []byte {
	eaePRK := hpkeLabeledExtract(hpkeKEMSuiteID, nil, "eae_prk", dh)
	return hpkeLabeledExpand(eaePRK, hpkeKEMSuiteID, "shared_secret", kemContext, sha256.Size)
}

func hpkeSeal(sharedSecret, info, plaintext, aad []byte) ([]byte, error) {
	key, nonce := hpkeKeySchedule(sharedSecret, info)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce, plaintext, aad), nil
}

func hpkeOpen(sharedSecret, info, ciphertext, aad []byte) ([]byte, error) {
	key, nonce := hpkeKeySchedule(sharedSecret, info)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrEnvelopeAuthFailed
	}
	return plaintext, nil
}

func hpkeKeySchedule(sharedSecret, info []byte) ([]byte, []byte) {
	pskIDHash := hpkeLabeledExtract(hpkeSuiteID, nil, "psk_id_hash", nil)
	infoHash := hpkeLabeledExtract(hpkeSuiteID, nil, "info_hash", info)
	context := append([]byte{0x00}, pskIDHash...)
	context = append(context, infoHash...)
	secret := hpkeLabeledExtract(hpkeSuiteID, sharedSecret, "secret", nil)
	key := hpkeLabeledExpand(secret, hpkeSuiteID, "key", context, AES256GCMKeyBytes)
	nonce := hpkeLabeledExpand(secret, hpkeSuiteID, "base_nonce", context, AESGCMNonceBytes)
	return key, nonce
}

func hpkeLabeledExtract(suiteID []byte, salt []byte, label string, ikm []byte) []byte {
	labeledIKM := append(append(append([]byte{}, hpkeVersionLabel...), suiteID...), []byte(label)...)
	labeledIKM = append(labeledIKM, ikm...)
	return hkdfExtract(salt, labeledIKM)
}

func hpkeLabeledExpand(prk []byte, suiteID []byte, label string, info []byte, length int) []byte {
	labeledInfo := make([]byte, 2, 2+len(hpkeVersionLabel)+len(suiteID)+len(label)+len(info))
	binary.BigEndian.PutUint16(labeledInfo, uint16(length))
	labeledInfo = append(labeledInfo, hpkeVersionLabel...)
	labeledInfo = append(labeledInfo, suiteID...)
	labeledInfo = append(labeledInfo, []byte(label)...)
	labeledInfo = append(labeledInfo, info...)
	return hkdfExpand(prk, labeledInfo, length)
}

func hkdfExtract(salt, ikm []byte) []byte {
	if salt == nil {
		salt = make([]byte, sha256.Size)
	}
	mac := hmac.New(sha256.New, salt)
	_, _ = mac.Write(ikm)
	return mac.Sum(nil)
}

func hkdfExpand(prk, info []byte, length int) []byte {
	var result []byte
	var previous []byte
	counter := byte(1)
	for len(result) < length {
		mac := hmac.New(sha256.New, prk)
		_, _ = mac.Write(previous)
		_, _ = mac.Write(info)
		_, _ = mac.Write([]byte{counter})
		previous = mac.Sum(nil)
		result = append(result, previous...)
		counter++
	}
	return result[:length]
}
