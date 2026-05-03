package auditarchive

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestArchiveWritesVerifiedArtifactSet(t *testing.T) {
	body := []byte("{}\n{}\n")
	digest := sha256.Sum256(body)
	result, err := Archive(body, hex.EncodeToString(digest[:]), "2", t.TempDir(), time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))
	if err != nil {
		t.Fatalf("Archive() error = %v", err)
	}
	for _, path := range []string{result.ExportPath, result.SHA256Path, result.EventsPath, result.ManifestPath} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected archive file %s: %v", path, err)
		}
	}
	if filepath.Base(result.Directory) != "20260102T030405Z" {
		t.Fatalf("unexpected archive directory: %s", result.Directory)
	}
	if !result.Verification.Valid || result.Verification.Events != 2 {
		t.Fatalf("unexpected verification result: %+v", result.Verification)
	}
}

func TestArchiveRejectsInvalidDigest(t *testing.T) {
	_, err := Archive([]byte("{}\n"), "bad", "1", t.TempDir(), time.Now())
	if err == nil {
		t.Fatal("expected invalid digest error")
	}
}
