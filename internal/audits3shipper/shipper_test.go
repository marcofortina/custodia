package audits3shipper

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"custodia/internal/auditarchive"
)

func TestShipArchiveUploadsObjectLockedBundle(t *testing.T) {
	body := []byte("{}\n")
	digest := sha256.Sum256(body)
	archiveRoot := filepath.Join(t.TempDir(), "archive")
	archive, err := auditarchive.Archive(body, hex.EncodeToString(digest[:]), "1", archiveRoot, time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))
	if err != nil {
		t.Fatalf("Archive() error = %v", err)
	}
	var seen []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.URL.Path)
		if r.Method != http.MethodPut {
			t.Fatalf("method = %s, want PUT", r.Method)
		}
		if r.Header.Get("X-Amz-Object-Lock-Mode") != "COMPLIANCE" {
			t.Fatalf("missing object lock mode: %q", r.Header.Get("X-Amz-Object-Lock-Mode"))
		}
		if r.Header.Get("X-Amz-Object-Lock-Retain-Until-Date") == "" {
			t.Fatal("missing retain-until header")
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
			t.Fatalf("missing SigV4 authorization: %q", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	result, err := ShipArchive(context.Background(), archive.Directory, Config{
		Endpoint:        server.URL,
		Region:          "us-east-1",
		Bucket:          "custodia-audit",
		Prefix:          "exports",
		AccessKeyID:     "minio",
		SecretAccessKey: "minio-secret",
		ObjectLockMode:  "COMPLIANCE",
		RetainUntil:     time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC),
		Client:          server.Client(),
		Now:             func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("ShipArchive() error = %v", err)
	}
	if len(seen) != 4 {
		t.Fatalf("uploaded %d objects, want 4: %#v", len(seen), seen)
	}
	if result.Objects["custodia-audit.jsonl"].SHA256 != hex.EncodeToString(digest[:]) {
		t.Fatalf("unexpected export digest: %#v", result.Objects["custodia-audit.jsonl"])
	}
}

func TestShipArchiveRequiresObjectLockRetention(t *testing.T) {
	_, err := ShipArchive(context.Background(), t.TempDir(), Config{Endpoint: "http://127.0.0.1", Region: "us-east-1", Bucket: "bucket", AccessKeyID: "key", SecretAccessKey: "secret"})
	if err != ErrObjectLockMissing {
		t.Fatalf("ShipArchive() error = %v, want %v", err, ErrObjectLockMissing)
	}
}
