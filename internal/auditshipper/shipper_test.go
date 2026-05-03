package auditshipper

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"custodia/internal/auditarchive"
)

func TestShipArchiveCopiesVerifiedBundle(t *testing.T) {
	body := []byte("{}\n")
	digest := sha256.Sum256(body)
	archiveRoot := filepath.Join(t.TempDir(), "archive")
	archive, err := auditarchive.Archive(body, hex.EncodeToString(digest[:]), "1", archiveRoot, time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))
	if err != nil {
		t.Fatalf("Archive() error = %v", err)
	}
	sinkRoot := filepath.Join(t.TempDir(), "sink")
	shipment, err := ShipArchive(archive.Directory, sinkRoot, time.Date(2026, 1, 2, 4, 5, 6, 0, time.UTC))
	if err != nil {
		t.Fatalf("ShipArchive() error = %v", err)
	}
	for _, path := range []string{shipment.ManifestPath, filepath.Join(shipment.SinkDirectory, "custodia-audit.jsonl"), filepath.Join(shipment.SinkDirectory, "manifest.json")} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected shipped file %s: %v", path, err)
		}
	}
	if got := shipment.Files["custodia-audit.jsonl"]; got != hex.EncodeToString(digest[:]) {
		t.Fatalf("shipped digest = %q", got)
	}
}

func TestShipArchiveRejectsMismatchedBundle(t *testing.T) {
	body := []byte("{}\n")
	digest := sha256.Sum256(body)
	archiveRoot := filepath.Join(t.TempDir(), "archive")
	archive, err := auditarchive.Archive(body, hex.EncodeToString(digest[:]), "1", archiveRoot, time.Now())
	if err != nil {
		t.Fatalf("Archive() error = %v", err)
	}
	if err := os.WriteFile(archive.SHA256Path, []byte("0000000000000000000000000000000000000000000000000000000000000000\n"), 0o640); err != nil {
		t.Fatalf("tamper sha256: %v", err)
	}
	_, err = ShipArchive(archive.Directory, filepath.Join(t.TempDir(), "sink"), time.Now())
	if err == nil {
		t.Fatal("expected tampered bundle to be rejected")
	}
}
