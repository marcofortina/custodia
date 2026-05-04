package clientcrypto

import (
	"bytes"
	"strings"
	"testing"
)

func TestSealOpenContentAES256GCM(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, AES256GCMKeyBytes)
	nonce := bytes.Repeat([]byte{0x24}, AESGCMNonceBytes)
	plaintext := []byte("database password")
	aad := []byte(`{"version":"custodia.client-crypto.v1"}`)

	ciphertext, err := SealContentAES256GCM(key, nonce, plaintext, aad)
	if err != nil {
		t.Fatalf("SealContentAES256GCM() error = %v", err)
	}
	if len(ciphertext) != len(plaintext)+AESGCMTagBytes {
		t.Fatalf("ciphertext length = %d, want %d", len(ciphertext), len(plaintext)+AESGCMTagBytes)
	}

	opened, err := OpenContentAES256GCM(key, nonce, ciphertext, aad)
	if err != nil {
		t.Fatalf("OpenContentAES256GCM() error = %v", err)
	}
	if string(opened) != string(plaintext) {
		t.Fatalf("opened plaintext = %q, want %q", opened, plaintext)
	}
}

func TestOpenContentAES256GCMRejectsAADMismatch(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, AES256GCMKeyBytes)
	nonce := bytes.Repeat([]byte{0x24}, AESGCMNonceBytes)
	ciphertext, err := SealContentAES256GCM(key, nonce, []byte("secret"), []byte("aad-one"))
	if err != nil {
		t.Fatalf("SealContentAES256GCM() error = %v", err)
	}
	if _, err := OpenContentAES256GCM(key, nonce, ciphertext, []byte("aad-two")); err == nil {
		t.Fatal("OpenContentAES256GCM() error = nil, want auth failure")
	}
}

func TestSealContentAES256GCMRejectsInvalidKeyAndNonce(t *testing.T) {
	if _, err := SealContentAES256GCM([]byte("short"), make([]byte, AESGCMNonceBytes), nil, nil); err == nil {
		t.Fatal("SealContentAES256GCM() error = nil, want invalid key")
	}
	if _, err := SealContentAES256GCM(make([]byte, AES256GCMKeyBytes), []byte("short"), nil, nil); err == nil {
		t.Fatal("SealContentAES256GCM() error = nil, want invalid nonce")
	}
}

func TestContentErrorsAreStable(t *testing.T) {
	if !strings.Contains(ErrContentAuthFailed.Error(), "authentication") {
		t.Fatalf("ErrContentAuthFailed = %q", ErrContentAuthFailed.Error())
	}
}
