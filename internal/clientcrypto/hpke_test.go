package clientcrypto

import (
	"bytes"
	"testing"
)

func TestSealOpenHPKEV1Envelope(t *testing.T) {
	recipientPrivateKey := bytes.Repeat([]byte{0x31}, 32)
	ephemeralPrivateKey := bytes.Repeat([]byte{0x42}, 32)
	dek := bytes.Repeat([]byte{0x51}, AES256GCMKeyBytes)
	aad := []byte("canonical aad")
	recipientPublicKey, err := DeriveX25519PublicKey(recipientPrivateKey)
	if err != nil {
		t.Fatalf("DeriveX25519PublicKey() error = %v", err)
	}

	envelope, err := SealHPKEV1Envelope(recipientPublicKey, ephemeralPrivateKey, dek, aad)
	if err != nil {
		t.Fatalf("SealHPKEV1Envelope() error = %v", err)
	}
	if len(envelope) != x25519PublicKeyBytes+AES256GCMKeyBytes+AESGCMTagBytes {
		t.Fatalf("envelope length = %d", len(envelope))
	}
	opened, err := OpenHPKEV1Envelope(recipientPrivateKey, envelope, aad)
	if err != nil {
		t.Fatalf("OpenHPKEV1Envelope() error = %v", err)
	}
	if !bytes.Equal(opened, dek) {
		t.Fatal("opened DEK mismatch")
	}
}

func TestOpenHPKEV1EnvelopeRejectsWrongRecipient(t *testing.T) {
	recipientPrivateKey := bytes.Repeat([]byte{0x31}, 32)
	wrongRecipientPrivateKey := bytes.Repeat([]byte{0x32}, 32)
	ephemeralPrivateKey := bytes.Repeat([]byte{0x42}, 32)
	recipientPublicKey, err := DeriveX25519PublicKey(recipientPrivateKey)
	if err != nil {
		t.Fatalf("DeriveX25519PublicKey() error = %v", err)
	}
	envelope, err := SealHPKEV1Envelope(recipientPublicKey, ephemeralPrivateKey, bytes.Repeat([]byte{0x51}, 32), []byte("aad"))
	if err != nil {
		t.Fatalf("SealHPKEV1Envelope() error = %v", err)
	}
	if _, err := OpenHPKEV1Envelope(wrongRecipientPrivateKey, envelope, []byte("aad")); err == nil {
		t.Fatal("OpenHPKEV1Envelope() error = nil, want wrong-recipient failure")
	}
}

func TestOpenHPKEV1EnvelopeRejectsAADMismatch(t *testing.T) {
	recipientPrivateKey := bytes.Repeat([]byte{0x31}, 32)
	ephemeralPrivateKey := bytes.Repeat([]byte{0x42}, 32)
	recipientPublicKey, err := DeriveX25519PublicKey(recipientPrivateKey)
	if err != nil {
		t.Fatalf("DeriveX25519PublicKey() error = %v", err)
	}
	envelope, err := SealHPKEV1Envelope(recipientPublicKey, ephemeralPrivateKey, bytes.Repeat([]byte{0x51}, 32), []byte("aad-one"))
	if err != nil {
		t.Fatalf("SealHPKEV1Envelope() error = %v", err)
	}
	if _, err := OpenHPKEV1Envelope(recipientPrivateKey, envelope, []byte("aad-two")); err == nil {
		t.Fatal("OpenHPKEV1Envelope() error = nil, want AAD mismatch failure")
	}
}

func TestEnvelopeEncodingRoundTrip(t *testing.T) {
	original := append(bytes.Repeat([]byte{0x11}, x25519PublicKeyBytes), bytes.Repeat([]byte{0x22}, AES256GCMKeyBytes+AESGCMTagBytes)...)
	encoded := EncodeEnvelope(original)
	decoded, err := DecodeEnvelope(encoded)
	if err != nil {
		t.Fatalf("DecodeEnvelope() error = %v", err)
	}
	if !bytes.Equal(decoded, original) {
		t.Fatal("decoded envelope mismatch")
	}
}
