package client

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestExternalGoConsumerCanUsePublicTransportTypes(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	moduleRoot := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", ".."))
	tmp := t.TempDir()
	fakeSQLite := filepath.Join(tmp, "fake-modernc-sqlite")
	if err := os.MkdirAll(fakeSQLite, 0o700); err != nil {
		t.Fatalf("mkdir fake sqlite module: %v", err)
	}
	if err := os.WriteFile(filepath.Join(fakeSQLite, "go.mod"), []byte("module modernc.org/sqlite\n"), 0o600); err != nil {
		t.Fatalf("write fake sqlite go.mod: %v", err)
	}
	goMod := "module external.example/custodia-consumer\n\nrequire custodia v0.0.0\n\nreplace custodia => " + moduleRoot + "\nreplace modernc.org/sqlite => " + fakeSQLite + "\n"
	if err := os.WriteFile(filepath.Join(tmp, "go.mod"), []byte(goMod), 0o600); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "main_test.go"), []byte(`package consumer

import (
    "testing"

    custodia "custodia/pkg/client"
)

func TestPublicTypesCompile(t *testing.T) {
    _ = custodia.Config{ServerURL: "https://vault.example"}
    _ = custodia.CreateSecretPayload{
        Name: "secret",
        Ciphertext: "Y2lwaGVy",
        Envelopes: []custodia.RecipientEnvelope{{ClientID: "client_alice", Envelope: "ZW52"}},
        Permissions: custodia.PermissionRead,
    }
    _ = custodia.SecretReadResponse{SecretID: "secret", VersionID: "version"}
    _ = custodia.OperationalStatus{Status: "ok", Build: custodia.BuildInfo{Version: "dev"}}
    _ = custodia.RuntimeDiagnostics{Goroutines: 1}
    _ = custodia.RevocationStatus{Configured: true}
    _ = custodia.AuditEvent{Action: "secret.read", ResourceType: "secret", Outcome: "success"}
}

func TestPublicMethodSignaturesCompile(t *testing.T) {
    var _ func(*custodia.Client) (custodia.ClientInfo, error) = (*custodia.Client).CurrentClientInfo
    var _ func(*custodia.Client, custodia.ClientListFilters) ([]custodia.ClientInfo, error) = (*custodia.Client).ListClientInfos
    var _ func(*custodia.Client, string) (custodia.SecretReadResponse, error) = (*custodia.Client).GetSecretPayload
    var _ func(*custodia.Client, custodia.CreateSecretPayload) (custodia.SecretVersionRef, error) = (*custodia.Client).CreateSecretPayload
    var _ func(*custodia.Client, string, custodia.ShareSecretPayload) error = (*custodia.Client).ShareSecretPayload
    var _ func(*custodia.Client) (custodia.OperationalStatus, error) = (*custodia.Client).StatusInfo
    var _ func(*custodia.Client) (custodia.BuildInfo, error) = (*custodia.Client).VersionInfo
    var _ func(*custodia.Client) (custodia.RuntimeDiagnostics, error) = (*custodia.Client).DiagnosticsInfo
    var _ func(*custodia.Client) (custodia.RevocationStatus, error) = (*custodia.Client).RevocationStatusInfo
    var _ func(*custodia.Client, string) (custodia.RevocationSerialStatus, error) = (*custodia.Client).RevocationSerialStatusInfo
    var _ func(*custodia.Client, custodia.AuditEventFilters) ([]custodia.AuditEvent, error) = (*custodia.Client).ListAuditEventMetadata
    var _ func(*custodia.Client, custodia.AuditEventFilters) (custodia.AuditExportArtifact, error) = (*custodia.Client).ExportAuditEventArtifact
}
`), 0o600); err != nil {
		t.Fatalf("write consumer test: %v", err)
	}
	cmd := exec.Command("go", "test", "-mod=mod", ".")
	cmd.Dir = tmp
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("external consumer go test failed: %v\n%s", err, string(output))
	}
}
