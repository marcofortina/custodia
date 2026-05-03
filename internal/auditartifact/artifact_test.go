package auditartifact

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
)

func TestVerifyAuditArtifact(t *testing.T) {
	body := []byte("{}\n{}\n")
	digest := sha256.Sum256(body)
	result, err := Verify(body, hex.EncodeToString(digest[:]), "2")
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if !result.Valid || result.Events != 2 || result.ExpectedEvents != 2 {
		t.Fatalf("unexpected verification result: %+v", result)
	}
}

func TestVerifyAuditArtifactRejectsDigestMismatch(t *testing.T) {
	body := []byte("{}\n")
	badDigest := "0000000000000000000000000000000000000000000000000000000000000000"
	result, err := Verify(body, badDigest, "1")
	if !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("Verify() error = %v, want %v", err, ErrDigestMismatch)
	}
	if result.Valid {
		t.Fatalf("expected invalid result: %+v", result)
	}
}

func TestVerifyAuditArtifactRejectsEventMismatch(t *testing.T) {
	body := []byte("{}\n")
	digest := sha256.Sum256(body)
	result, err := Verify(body, hex.EncodeToString(digest[:]), "2")
	if !errors.Is(err, ErrEventMismatch) {
		t.Fatalf("Verify() error = %v, want %v", err, ErrEventMismatch)
	}
	if result.Valid {
		t.Fatalf("expected invalid result: %+v", result)
	}
}
