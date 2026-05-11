// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"custodia/internal/auditarchive"
)

func TestUsageMentionsDoctorCommand(t *testing.T) {
	oldStderr := os.Stderr
	readPipe, writePipe, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = writePipe
	usage()
	if err := writePipe.Close(); err != nil {
		t.Fatal(err)
	}
	os.Stderr = oldStderr
	body, err := io.ReadAll(readPipe)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "custodia-admin doctor [--server-config FILE] [--signer-config FILE]") {
		t.Fatalf("usage does not mention doctor command: %s", string(body))
	}
}

func TestRunWebTOTPGenerateOutputsJSON(t *testing.T) {
	var out bytes.Buffer
	if err := runWebTOTPGenerate([]string{"--issuer", "Custodia", "--account", "admin", "--format", "json"}, &out); err != nil {
		t.Fatalf("runWebTOTPGenerate() error = %v", err)
	}
	var payload map[string]string
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("invalid json output: %v", err)
	}
	if payload["issuer"] != "Custodia" || payload["account"] != "admin" {
		t.Fatalf("unexpected payload labels: %#v", payload)
	}
	if payload["totp_secret"] == "" {
		t.Fatal("expected generated TOTP secret")
	}
	if !strings.HasPrefix(payload["provisioning_uri"], "otpauth://totp/Custodia:admin?") {
		t.Fatalf("unexpected provisioning URI: %q", payload["provisioning_uri"])
	}
}

func TestRunWebTOTPGenerateRejectsUnsupportedFormat(t *testing.T) {
	if err := runWebTOTPGenerate([]string{"--format", "xml"}, io.Discard); err == nil {
		t.Fatal("expected unsupported format error")
	}
}

func TestVaultAdminPathEscapeProtectsDynamicSegments(t *testing.T) {
	if got := pathEscape("tenant/client"); got != "tenant%2Fclient" {
		t.Fatalf("unexpected escaped path segment: %q", got)
	}
}

func TestAddQueryFilterTrimsValues(t *testing.T) {
	query := url.Values{}
	addQueryFilter(query, "client_id", " client_alice ")
	if got := query.Get("client_id"); got != "client_alice" {
		t.Fatalf("unexpected query value: %q", got)
	}
}

func TestRunClientCommandsRejectInvalidClientIDs(t *testing.T) {
	if err := runClientGet(&cliConfig{}, []string{"--client-id", "client bad"}); err == nil {
		t.Fatal("expected invalid client get id error")
	}
	if err := runClientCreate(&cliConfig{}, []string{"--client-id", "client bad", "--mtls-subject", "subject"}); err == nil {
		t.Fatal("expected invalid client create id error")
	}
	if err := runClientRevoke(&cliConfig{}, []string{"--client-id", "client bad"}); err == nil {
		t.Fatal("expected invalid client revoke id error")
	}
}

func TestRunClientCreateRejectsInvalidMTLSSubject(t *testing.T) {
	err := runClientCreate(&cliConfig{}, []string{"--client-id", "client_good", "--mtls-subject", "bad\nsubject"})
	if err == nil {
		t.Fatal("expected invalid mtls subject error")
	}
}

func TestRunClientListRejectsInvalidLimit(t *testing.T) {
	err := runClientList(&cliConfig{}, []string{"--limit", "501"})
	if err == nil {
		t.Fatal("expected invalid limit error")
	}
}

func TestRunClientRevokeRejectsInvalidReason(t *testing.T) {
	err := runClientRevoke(&cliConfig{}, []string{"--client-id", "client_bob", "--reason", "bad\nreason"})
	if err == nil {
		t.Fatal("expected invalid reason error")
	}
}

func TestRunAuditExportRejectsInvalidLimit(t *testing.T) {
	err := runAuditExport(&cliConfig{}, []string{"--limit", "0"})
	if err == nil {
		t.Fatal("expected invalid limit error")
	}
}

func TestRunClientListRejectsInvalidActiveFilter(t *testing.T) {
	err := runClientList(&cliConfig{}, []string{"--active", "maybe"})
	if err == nil {
		t.Fatal("expected invalid active filter error")
	}
}

func TestRunSecretCommandsRejectInvalidKeyspace(t *testing.T) {
	if err := runSecretVersions(&cliConfig{}, []string{"--key", "bad\nkey"}); err == nil {
		t.Fatal("expected invalid secret version key error")
	}
	if err := runAccessList(&cliConfig{}, []string{"--namespace", "bad\nnamespace", "--key", "user:sys"}); err == nil {
		t.Fatal("expected invalid access list namespace error")
	}
	if err := runAccessGrantRequest(&cliConfig{}, []string{"--key", "", "--client-id", "client_bob", "--permissions", "read"}); err == nil {
		t.Fatal("expected missing grant request key error")
	}
	if err := runAccessGrantRequest(&cliConfig{}, []string{"--key", "user:sys", "--client-id", "client bad", "--permissions", "read"}); err == nil {
		t.Fatal("expected invalid grant request client id error")
	}
	if err := runAccessGrantRequest(&cliConfig{}, []string{"--key", "user:sys", "--client-id", "client_bob", "--permissions", "read", "--version-id", "latest"}); err == nil {
		t.Fatal("expected invalid grant request version id error")
	}
}

func TestRunSecretVersionsRejectsInvalidLimit(t *testing.T) {
	err := runSecretVersions(&cliConfig{}, []string{"--key", "user:sys", "--limit", "501"})
	if err == nil {
		t.Fatal("expected invalid limit error")
	}
}

func TestRunAccessListRejectsInvalidLimit(t *testing.T) {
	err := runAccessList(&cliConfig{}, []string{"--key", "user:sys", "--limit", "0"})
	if err == nil {
		t.Fatal("expected invalid limit error")
	}
}

func TestRunAccessRequestsRejectsInvalidFilters(t *testing.T) {
	if err := runAccessRequests(&cliConfig{}, []string{"--namespace", "bad\nnamespace"}); err == nil {
		t.Fatal("expected invalid namespace filter error")
	}
	if err := runAccessRequests(&cliConfig{}, []string{"--key", "bad\nkey"}); err == nil {
		t.Fatal("expected invalid key filter error")
	}
	if err := runAccessRequests(&cliConfig{}, []string{"--status", "done"}); err == nil {
		t.Fatal("expected invalid status filter error")
	}
	if err := runAccessRequests(&cliConfig{}, []string{"--client-id", "client bad"}); err == nil {
		t.Fatal("expected invalid client id filter error")
	}
	if err := runAccessRequests(&cliConfig{}, []string{"--requested-by-client-id", "client bad"}); err == nil {
		t.Fatal("expected invalid requester filter error")
	}
}

func TestRunAccessGrantRequestRejectsInvalidExpiresAt(t *testing.T) {
	err := runAccessGrantRequest(&cliConfig{}, []string{
		"--key", "user:sys",
		"--client-id", "client_bob",
		"--permissions", "read",
		"--expires-at", "tomorrow",
	})
	if err == nil {
		t.Fatal("expected invalid expires-at error")
	}
}

func TestRunAuditCommandsRejectInvalidFilters(t *testing.T) {
	if err := runAuditList(&cliConfig{}, []string{"--outcome", "maybe"}); err == nil {
		t.Fatal("expected invalid audit list outcome error")
	}
	if err := runAuditList(&cliConfig{}, []string{"--action", "bad action"}); err == nil {
		t.Fatal("expected invalid audit list action error")
	}
	if err := runAuditExport(&cliConfig{}, []string{"--actor-client-id", "client bad"}); err == nil {
		t.Fatal("expected invalid audit export actor error")
	}
	if err := runAuditExport(&cliConfig{}, []string{"--resource-type", "bad type"}); err == nil {
		t.Fatal("expected invalid audit export resource type error")
	}
	if err := runAuditExport(&cliConfig{}, []string{"--resource-id", "bad\nresource"}); err == nil {
		t.Fatal("expected invalid audit export resource id error")
	}
}

func TestRunClientIssueValidatesArgsBeforeNetwork(t *testing.T) {
	if err := runClientIssue(&cliConfig{}, []string{"--client-id", "client bad", "--out-dir", t.TempDir()}); err == nil {
		t.Fatal("expected invalid client id error")
	}
	if err := runClientIssue(&cliConfig{}, []string{"--client-id", "client_alice"}); err == nil {
		t.Fatal("expected missing out-dir error")
	}
	if err := runClientIssue(&cliConfig{}, []string{"--client-id", "client_alice", "--out-dir", t.TempDir(), "--ttl-hours", "-1"}); err == nil {
		t.Fatal("expected invalid ttl error")
	}
}

func TestRunClientIssueRefusesExistingOutputBeforeNetwork(t *testing.T) {
	dir := t.TempDir()
	paths := clientIssueOutputPaths(dir, "client_alice")
	if err := os.WriteFile(paths.privateKey, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := runClientIssue(&cliConfig{}, []string{"--client-id", "client_alice", "--out-dir", dir})
	if err == nil || !strings.Contains(err.Error(), "output already exists") {
		t.Fatalf("expected existing output error before network, got: %v", err)
	}
}

func TestClientIssueOutputPathsAreSafe(t *testing.T) {
	paths := clientIssueOutputPaths("/tmp/custodia", "tenant:client")
	if !strings.HasSuffix(paths.privateKey, "tenant_client.key") || !strings.HasSuffix(paths.bundle, "tenant_client-mtls.zip") {
		t.Fatalf("unexpected issue paths: %+v", paths)
	}
}

func TestRunClientCSRRejectsInvalidClientID(t *testing.T) {
	err := runClientCSR([]string{"--client-id", "client bad", "--private-key-out", "key.pem", "--csr-out", "client.csr"})
	if err == nil {
		t.Fatal("expected invalid client csr id error")
	}
}

func TestRunClientCSRWritesFiles(t *testing.T) {
	dir := t.TempDir()
	keyPath := dir + "/client.key"
	csrPath := dir + "/client.csr"
	if err := runClientCSR([]string{"--client-id", "client_alice", "--private-key-out", keyPath, "--csr-out", csrPath}); err != nil {
		t.Fatalf("runClientCSR() error = %v", err)
	}
	if err := runClientCSR([]string{"--client-id", "client_alice", "--private-key-out", keyPath, "--csr-out", csrPath}); err == nil {
		t.Fatal("expected exclusive write error for existing files")
	}
}

func TestRunCertificateSignRejectsInvalidArgs(t *testing.T) {
	if err := runCertificateSign(&cliConfig{}, []string{"--client-id", "client bad", "--csr-file", "client.csr"}); err == nil {
		t.Fatal("expected invalid certificate sign client id error")
	}
	if err := runCertificateSign(&cliConfig{}, []string{"--client-id", "client_alice", "--csr-file", "client.csr", "--ttl-hours", "-1"}); err == nil {
		t.Fatal("expected invalid certificate sign ttl error")
	}
}

func TestRunCertificateExtractWritesClientCertificate(t *testing.T) {
	outDir := filepath.Join(t.TempDir(), "lite")
	if err := runCABootstrapLocal([]string{"--out-dir", outDir, "--admin-client-id", "admin", "--server-name", "localhost"}); err != nil {
		t.Fatalf("runCABootstrapLocal() error = %v", err)
	}
	certificatePEM, err := os.ReadFile(filepath.Join(outDir, "admin.crt"))
	if err != nil {
		t.Fatalf("ReadFile(admin.crt) error = %v", err)
	}
	payload, err := json.Marshal(map[string]string{"certificate_pem": string(certificatePEM)})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	signerJSON := filepath.Join(t.TempDir(), "client.sign.json")
	if err := os.WriteFile(signerJSON, payload, 0o600); err != nil {
		t.Fatalf("WriteFile(sign json) error = %v", err)
	}
	certificateOut := filepath.Join(t.TempDir(), "client.crt")
	if err := runCertificateExtract([]string{"--input", signerJSON, "--certificate-out", certificateOut}); err != nil {
		t.Fatalf("runCertificateExtract() error = %v", err)
	}
	written, err := os.ReadFile(certificateOut)
	if err != nil {
		t.Fatalf("ReadFile(certificateOut) error = %v", err)
	}
	if string(written) != strings.TrimSpace(string(certificatePEM))+"\n" {
		t.Fatalf("unexpected certificate output: %q", string(written))
	}
	info, err := os.Stat(certificateOut)
	if err != nil {
		t.Fatalf("Stat(certificateOut) error = %v", err)
	}
	if got := info.Mode().Perm(); got != 0o644 {
		t.Fatalf("certificate mode = %o, want 0644", got)
	}
	if err := runCertificateExtract([]string{"--input", signerJSON, "--certificate-out", certificateOut}); err == nil {
		t.Fatal("expected exclusive output write error")
	}
}

func TestRunCertificateBundleWritesLocalArchive(t *testing.T) {
	outDir := filepath.Join(t.TempDir(), "lite")
	if err := runCABootstrapLocal([]string{"--out-dir", outDir, "--admin-client-id", "admin", "--server-name", "localhost"}); err != nil {
		t.Fatalf("runCABootstrapLocal() error = %v", err)
	}
	bundleOut := filepath.Join(t.TempDir(), "client.zip")
	if err := runCertificateBundle([]string{
		"--certificate", filepath.Join(outDir, "admin.crt"),
		"--private-key", filepath.Join(outDir, "admin.key"),
		"--ca", filepath.Join(outDir, "ca.crt"),
		"--out", bundleOut,
	}); err != nil {
		t.Fatalf("runCertificateBundle() error = %v", err)
	}
	info, err := os.Stat(bundleOut)
	if err != nil {
		t.Fatalf("Stat(bundleOut) error = %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("bundle mode = %o, want 0600", got)
	}
	reader, err := zip.OpenReader(bundleOut)
	if err != nil {
		t.Fatalf("OpenReader(bundleOut) error = %v", err)
	}
	defer reader.Close()

	entries := map[string]os.FileMode{}
	for _, file := range reader.File {
		entries[file.Name] = file.Mode().Perm()
	}
	for name, wantMode := range map[string]os.FileMode{"client.crt": 0o644, "client.key": 0o600, "ca.crt": 0o644, "README.txt": 0o644} {
		if gotMode, ok := entries[name]; !ok {
			t.Fatalf("missing bundle entry %s", name)
		} else if gotMode != wantMode {
			t.Fatalf("bundle entry %s mode = %o, want %o", name, gotMode, wantMode)
		}
	}
	if err := runCertificateBundle([]string{
		"--certificate", filepath.Join(outDir, "admin.crt"),
		"--private-key", filepath.Join(outDir, "admin.key"),
		"--ca", filepath.Join(outDir, "ca.crt"),
		"--out", bundleOut,
	}); err == nil {
		t.Fatal("expected exclusive bundle output write error")
	}
}

func TestRunCertificateBundleRejectsInvalidInputs(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(bad, []byte("not pem\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(bad) error = %v", err)
	}
	outDir := filepath.Join(dir, "lite")
	if err := runCABootstrapLocal([]string{"--out-dir", outDir, "--admin-client-id", "admin", "--server-name", "localhost"}); err != nil {
		t.Fatalf("runCABootstrapLocal() error = %v", err)
	}
	if err := runCertificateBundle([]string{
		"--certificate", bad,
		"--private-key", filepath.Join(outDir, "admin.key"),
		"--ca", filepath.Join(outDir, "ca.crt"),
		"--out", filepath.Join(dir, "bad-cert.zip"),
	}); err == nil {
		t.Fatal("expected invalid client certificate error")
	}
	if err := runCertificateBundle([]string{
		"--certificate", filepath.Join(outDir, "admin.crt"),
		"--private-key", bad,
		"--ca", filepath.Join(outDir, "ca.crt"),
		"--out", filepath.Join(dir, "bad-key.zip"),
	}); err == nil {
		t.Fatal("expected invalid private key error")
	}
	if err := runCertificateBundle([]string{
		"--certificate", filepath.Join(outDir, "admin.crt"),
		"--private-key", filepath.Join(outDir, "admin.key"),
		"--ca", filepath.Join(outDir, "admin.crt"),
		"--out", filepath.Join(dir, "bad-ca.zip"),
	}); err == nil {
		t.Fatal("expected non-CA certificate error")
	}
}

func TestRunCertificateExtractRejectsInvalidPayloads(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"missing-pem.json": `{}`,
		"invalid-pem.json": `{"certificate_pem":"not a cert"}`,
	}
	for name, payload := range cases {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
			t.Fatalf("WriteFile(%s) error = %v", name, err)
		}
		if err := runCertificateExtract([]string{"--input", path, "--certificate-out", filepath.Join(dir, name+".crt")}); err == nil {
			t.Fatalf("expected extract error for %s", name)
		}
	}
}

func TestWriteAuditExportArtifacts(t *testing.T) {
	dir := t.TempDir()
	bodyPath := dir + "/audit.jsonl"
	shaPath := dir + "/audit.sha256"
	eventsPath := dir + "/audit.events"
	headers := http.Header{}
	headers.Set("X-Custodia-Audit-Export-SHA256", "abc123")
	headers.Set("X-Custodia-Audit-Export-Events", "2")
	if err := writeAuditExportArtifacts([]byte("{}\n{}\n"), headers, bodyPath, shaPath, eventsPath, nil); err != nil {
		t.Fatalf("writeAuditExportArtifacts() error = %v", err)
	}
	body, err := os.ReadFile(bodyPath)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != "{}\n{}\n" {
		t.Fatalf("unexpected body artifact: %q", string(body))
	}
	sha, err := os.ReadFile(shaPath)
	if err != nil {
		t.Fatalf("read sha: %v", err)
	}
	if string(sha) != "abc123\n" {
		t.Fatalf("unexpected sha artifact: %q", string(sha))
	}
	events, err := os.ReadFile(eventsPath)
	if err != nil {
		t.Fatalf("read events: %v", err)
	}
	if string(events) != "2\n" {
		t.Fatalf("unexpected events artifact: %q", string(events))
	}
}

func TestRunAuditVerifyExport(t *testing.T) {
	dir := t.TempDir()
	body := []byte("{}\n{}\n")
	digest := "3b00ba5361676a0a8152642a6edaf54a222bd409b5774b5b461ac8d1cee09cb4\n"
	bodyPath := dir + "/audit.jsonl"
	shaPath := dir + "/audit.sha256"
	eventsPath := dir + "/audit.events"
	if err := os.WriteFile(bodyPath, body, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := os.WriteFile(shaPath, []byte(digest), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := os.WriteFile(eventsPath, []byte("2\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := runAuditVerifyExport([]string{"--file", bodyPath, "--sha256-file", shaPath, "--events-file", eventsPath}); err != nil {
		t.Fatalf("runAuditVerifyExport() error = %v", err)
	}
}

func TestRunAuditVerifyExportRejectsMissingArgs(t *testing.T) {
	if err := runAuditVerifyExport(nil); err == nil {
		t.Fatal("expected missing args error")
	}
}

func TestRunAuditArchiveExportWritesBundle(t *testing.T) {
	dir := t.TempDir()
	bodyFile := dir + "/audit.jsonl"
	shaFile := dir + "/audit.sha256"
	eventsFile := dir + "/audit.events"
	archiveDir := dir + "/archive"
	body := []byte("{}\n")
	digest := sha256.Sum256(body)
	if err := os.WriteFile(bodyFile, body, 0o600); err != nil {
		t.Fatalf("write body: %v", err)
	}
	if err := os.WriteFile(shaFile, []byte(hex.EncodeToString(digest[:])+"\n"), 0o600); err != nil {
		t.Fatalf("write digest: %v", err)
	}
	if err := os.WriteFile(eventsFile, []byte("1\n"), 0o600); err != nil {
		t.Fatalf("write events: %v", err)
	}

	if err := runAuditArchiveExport([]string{"--file", bodyFile, "--sha256-file", shaFile, "--events-file", eventsFile, "--archive-dir", archiveDir}); err != nil {
		t.Fatalf("runAuditArchiveExport() error = %v", err)
	}
	entries, err := os.ReadDir(archiveDir)
	if err != nil {
		t.Fatalf("read archive dir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected one archive bundle, got %d", len(entries))
	}
}

func TestRunAuditShipArchiveRejectsMissingArgs(t *testing.T) {
	if err := runAuditShipArchive([]string{"--archive-dir", "bundle"}); err == nil {
		t.Fatal("expected missing sink dir error")
	}
}

func TestRunAuditShipArchiveCopiesBundle(t *testing.T) {
	body := []byte("{}\n")
	digest := sha256.Sum256(body)
	archiveRoot := filepath.Join(t.TempDir(), "archive")
	archive, err := auditarchive.Archive(body, hex.EncodeToString(digest[:]), "1", archiveRoot, time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))
	if err != nil {
		t.Fatalf("Archive() error = %v", err)
	}
	sinkRoot := filepath.Join(t.TempDir(), "sink")
	if err := runAuditShipArchive([]string{"--archive-dir", archive.Directory, "--sink-dir", sinkRoot}); err != nil {
		t.Fatalf("runAuditShipArchive() error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(sinkRoot, filepath.Base(archive.Directory), "shipment.json")); err != nil {
		t.Fatalf("expected shipment manifest: %v", err)
	}
}

func TestRunRevocationFetchCRLRejectsMissingOut(t *testing.T) {
	if err := runRevocationFetchCRL(&cliConfig{}, nil); err == nil {
		t.Fatal("expected missing output path error")
	}
}

func TestRunRevocationFetchCRLRefusesExistingFile(t *testing.T) {
	path := t.TempDir() + "/client.crl"
	if err := os.WriteFile(path, []byte("existing"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := runRevocationFetchCRL(&cliConfig{}, []string{"--out", path}); err == nil {
		t.Fatal("expected exclusive output write error")
	}
}

func TestRunProductionCheckRejectsUnsafeEnv(t *testing.T) {
	envFile := writeTestEnv(t, "CUSTODIA_DEV_INSECURE_HTTP=true\nCUSTODIA_STORE_BACKEND=memory\n")
	if err := runProductionCheck([]string{"--env-file", envFile}); err == nil {
		t.Fatal("expected production check error")
	}
}

func TestRunProductionCheckAcceptsHardenedEnv(t *testing.T) {
	envFile := writeTestEnv(t, `CUSTODIA_STORE_BACKEND=postgres
CUSTODIA_DATABASE_URL=postgres://db
CUSTODIA_RATE_LIMIT_BACKEND=valkey
CUSTODIA_VALKEY_URL=rediss://cache
CUSTODIA_TLS_CERT_FILE=/certs/api.crt
CUSTODIA_TLS_KEY_FILE=/certs/api.key
CUSTODIA_CLIENT_CA_FILE=/certs/ca.crt
CUSTODIA_CLIENT_CRL_FILE=/certs/client.crl
CUSTODIA_ADMIN_CLIENT_IDS=admin
CUSTODIA_WEB_MFA_REQUIRED=true
CUSTODIA_WEB_TOTP_SECRET=JBSWY3DPEHPK3PXP
CUSTODIA_WEB_SESSION_SECRET=0123456789abcdef0123456789abcdef
CUSTODIA_DEPLOYMENT_MODE=multi-region
CUSTODIA_DATABASE_HA_TARGET=cockroachdb-multi-region
CUSTODIA_AUDIT_SHIPMENT_SINK=s3://custodia-audit
CUSTODIA_SIGNER_KEY_PROVIDER=pkcs11
CUSTODIA_SIGNER_PKCS11_SIGN_COMMAND=/usr/local/bin/custodia-pkcs11-sign
CUSTODIA_SIGNER_TLS_CERT_FILE=/certs/signer.crt
CUSTODIA_SIGNER_TLS_KEY_FILE=/certs/signer.key
CUSTODIA_SIGNER_CLIENT_CA_FILE=/certs/admin-ca.crt
CUSTODIA_SIGNER_ADMIN_SUBJECTS=signer_admin
CUSTODIA_SIGNER_AUDIT_LOG_FILE=/audit/signer.jsonl
CUSTODIA_SIGNER_CRL_FILE=/certs/client.crl
`)
	if err := runProductionCheck([]string{"--env-file", envFile}); err != nil {
		t.Fatalf("runProductionCheck() error = %v", err)
	}
}

func TestRunProductionEvidenceCheckRejectsMissingEvidence(t *testing.T) {
	envFile := writeTestEnv(t, "CUSTODIA_EVIDENCE_HSM_ATTESTATION_FILE=/evidence/hsm.json\n")
	if err := runProductionEvidenceCheck([]string{"--env-file", envFile}); err == nil {
		t.Fatal("expected production evidence check error")
	}
}

func TestRunProductionEvidenceCheckAcceptsCompleteEvidence(t *testing.T) {
	envFile := writeTestEnv(t, `CUSTODIA_EVIDENCE_HSM_ATTESTATION_FILE=/evidence/hsm.json
CUSTODIA_EVIDENCE_WORM_RETENTION_FILE=/evidence/worm.json
CUSTODIA_EVIDENCE_DATABASE_HA_FILE=/evidence/database-ha.json
CUSTODIA_EVIDENCE_VALKEY_CLUSTER_FILE=/evidence/valkey.json
CUSTODIA_EVIDENCE_ZERO_TRUST_NETWORK_FILE=/evidence/network.json
CUSTODIA_EVIDENCE_AIR_GAP_BACKUP_FILE=/evidence/backup.json
CUSTODIA_EVIDENCE_PEN_TEST_FILE=/evidence/pentest.json
CUSTODIA_EVIDENCE_FORMAL_VERIFICATION_FILE=/evidence/formal.json
CUSTODIA_EVIDENCE_REVOCATION_DRILL_FILE=/evidence/revocation.json
CUSTODIA_EVIDENCE_RELEASE_CHECK_FILE=/evidence/release.json
`)
	if err := runProductionEvidenceCheck([]string{"--env-file", envFile}); err != nil {
		t.Fatalf("runProductionEvidenceCheck() error = %v", err)
	}
}

func writeTestEnv(t *testing.T, content string) string {
	t.Helper()
	path := t.TempDir() + "/custodia.env"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return path
}

func TestRunAuditShipArchiveS3RejectsMissingArgs(t *testing.T) {
	if err := runAuditShipArchiveS3([]string{"--archive-dir", "bundle"}); err == nil {
		t.Fatal("expected missing S3 args error")
	}
}

func TestRunAuditShipArchiveS3UploadsBundle(t *testing.T) {
	body := []byte("{}\n")
	digest := sha256.Sum256(body)
	archiveRoot := filepath.Join(t.TempDir(), "archive")
	archive, err := auditarchive.Archive(body, hex.EncodeToString(digest[:]), "1", archiveRoot, time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))
	if err != nil {
		t.Fatalf("Archive() error = %v", err)
	}
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Header.Get("X-Amz-Object-Lock-Mode") != "COMPLIANCE" {
			t.Fatalf("missing object lock mode: %q", r.Header.Get("X-Amz-Object-Lock-Mode"))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	err = runAuditShipArchiveS3([]string{
		"--archive-dir", archive.Directory,
		"--endpoint", server.URL,
		"--bucket", "custodia-audit",
		"--access-key-id", "minio",
		"--secret-access-key", "minio-secret",
		"--retain-until", "2027-01-02T03:04:05Z",
	})
	if err != nil {
		t.Fatalf("runAuditShipArchiveS3() error = %v", err)
	}
	if requests != 4 {
		t.Fatalf("requests = %d, want 4", requests)
	}
}

func TestRunRevocationCheckSerialRejectsMissingSerial(t *testing.T) {
	if err := runRevocationCheckSerial(&cliConfig{}, []string{}); err == nil {
		t.Fatal("expected missing serial error")
	}
}

func TestRunCABootstrapLocalWritesLiteArtifacts(t *testing.T) {
	outDir := filepath.Join(t.TempDir(), "lite")
	if err := runCABootstrapLocal([]string{"--out-dir", outDir, "--admin-client-id", "admin", "--server-name", "localhost", "--generate-ca-passphrase"}); err != nil {
		t.Fatalf("runCABootstrapLocal() error = %v", err)
	}
	for _, name := range []string{"ca.crt", "ca.key", "ca.pass", "client-ca.crt", "client.crl.pem", "server.crt", "server.key", "admin.crt", "admin.key", "custodia-server.yaml", "custodia-signer.yaml"} {
		if _, err := os.Stat(filepath.Join(outDir, name)); err != nil {
			t.Fatalf("missing generated %s: %v", name, err)
		}
	}
	configPayload, err := os.ReadFile(filepath.Join(outDir, "custodia-server.yaml"))
	if err != nil {
		t.Fatalf("ReadFile(config) error = %v", err)
	}
	for _, expected := range [][]byte{[]byte("profile: lite"), []byte("server:"), []byte("storage:"), []byte("tls:"), []byte("signer:"), []byte("bootstrap_clients:"), []byte("client_id: admin"), []byte("mtls_subject: admin"), []byte("admin_client_ids:"), []byte("- admin")} {
		if !bytes.Contains(configPayload, expected) {
			t.Fatalf("expected config payload to contain %q: %s", string(expected), string(configPayload))
		}
	}
	caKeyPayload, err := os.ReadFile(filepath.Join(outDir, "ca.key"))
	if err != nil {
		t.Fatalf("ReadFile(ca.key) error = %v", err)
	}
	if !bytes.Contains(caKeyPayload, []byte("ENCRYPTED PRIVATE KEY")) {
		t.Fatalf("expected encrypted ca key: %s", string(caKeyPayload))
	}
}

func TestRunCABootstrapLocalRefusesOverwrite(t *testing.T) {
	outDir := filepath.Join(t.TempDir(), "lite")
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "ca.crt"), []byte("existing"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := runCABootstrapLocal([]string{"--out-dir", outDir}); err == nil {
		t.Fatal("expected overwrite refusal")
	}
}

func TestRunMigrationPlanAcceptsLiteToFullConfigs(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "lite.yaml")
	target := filepath.Join(dir, "full.yaml")
	writeAdminTestFile(t, source, `profile: lite
storage:
  backend: sqlite
  database_url: "file:/var/lib/custodia/custodia.db"
signer:
  key_provider: file
`)
	writeAdminTestFile(t, target, `profile: full
storage:
  backend: postgres
  database_url: "postgres://custodia@db/custodia"
rate_limit:
  backend: valkey
  valkey_url: "rediss://valkey:6379/0"
deployment:
  database_ha_target: cockroachdb-multi-region
  audit_shipment_sink: s3-object-lock://custodia-audit
signer:
  key_provider: pkcs11
`)
	if err := runMigrationPlan([]string{"--source-config", source, "--target-config", target}); err != nil {
		t.Fatalf("runMigrationPlan() error = %v", err)
	}
}

func TestRunMigrationPlanWarnsForFullToLiteConfigs(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "full.yaml")
	target := filepath.Join(dir, "lite.yaml")
	writeAdminTestFile(t, source, `profile: full
storage:
  backend: postgres
  database_url: "postgres://custodia@db/custodia"
`)
	writeAdminTestFile(t, target, `profile: lite
storage:
  backend: sqlite
  database_url: "file:/var/lib/custodia/custodia.db"
`)
	if err := runMigrationPlan([]string{"--source-config", source, "--target-config", target}); err != nil {
		t.Fatalf("runMigrationPlan() full-to-lite warning path returned error: %v", err)
	}
}

func TestRunMigrationPlanRejectsUnsupportedDirection(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source.yaml")
	target := filepath.Join(dir, "target.yaml")
	writeAdminTestFile(t, source, `profile: lite
storage:
  backend: memory
`)
	writeAdminTestFile(t, target, `profile: lite
storage:
  backend: sqlite
`)
	if err := runMigrationPlan([]string{"--source-config", source, "--target-config", target}); err == nil {
		t.Fatal("expected unsupported direction error")
	}
}

func writeAdminTestFile(t *testing.T, path string, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("WriteFile(%s) error = %v", path, err)
	}
}

func TestRunLiteUpgradeCheckAcceptsPlannedEnvironment(t *testing.T) {
	dir := t.TempDir()
	liteEnv := filepath.Join(dir, "lite.env")
	fullEnv := filepath.Join(dir, "full.env")
	if err := os.WriteFile(liteEnv, []byte(`CUSTODIA_PROFILE=lite
CUSTODIA_STORE_BACKEND=sqlite
CUSTODIA_DATABASE_URL=file:/var/lib/custodia/custodia.db
CUSTODIA_SIGNER_KEY_PROVIDER=file
`), 0o600); err != nil {
		t.Fatalf("write lite env: %v", err)
	}
	if err := os.WriteFile(fullEnv, []byte(`CUSTODIA_PROFILE=full
CUSTODIA_STORE_BACKEND=postgres
CUSTODIA_DATABASE_URL=postgres://custodia@db/custodia
CUSTODIA_RATE_LIMIT_BACKEND=valkey
CUSTODIA_VALKEY_URL=rediss://valkey:6379/0
CUSTODIA_SIGNER_KEY_PROVIDER=pkcs11
CUSTODIA_AUDIT_SHIPMENT_SINK=s3-object-lock://custodia-audit
CUSTODIA_DATABASE_HA_TARGET=cockroachdb-multi-region
`), 0o600); err != nil {
		t.Fatalf("write full env: %v", err)
	}
	if err := runLiteUpgradeCheck([]string{"--lite-env-file", liteEnv, "--full-env-file", fullEnv}); err != nil {
		t.Fatalf("runLiteUpgradeCheck() error = %v", err)
	}
}

func TestRunLiteUpgradeCheckRejectsInvalidTarget(t *testing.T) {
	dir := t.TempDir()
	liteEnv := filepath.Join(dir, "lite.env")
	fullEnv := filepath.Join(dir, "full.env")
	if err := os.WriteFile(liteEnv, []byte(`CUSTODIA_PROFILE=lite
CUSTODIA_STORE_BACKEND=sqlite
CUSTODIA_DATABASE_URL=file:/var/lib/custodia/custodia.db
CUSTODIA_SIGNER_KEY_PROVIDER=file
`), 0o600); err != nil {
		t.Fatalf("write lite env: %v", err)
	}
	if err := os.WriteFile(fullEnv, []byte(`CUSTODIA_PROFILE=lite
CUSTODIA_STORE_BACKEND=sqlite
`), 0o600); err != nil {
		t.Fatalf("write full env: %v", err)
	}
	if err := runLiteUpgradeCheck([]string{"--lite-env-file", liteEnv, "--full-env-file", fullEnv}); err == nil {
		t.Fatal("expected invalid full target error")
	}
}

func TestDefaultAdminTransportLoadsServerConfig(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "custodia-server.yaml")
	writeAdminTestFile(t, configPath, `profile: lite
server:
  url: "https://custodia.example.internal:8443"
signer:
  client_cert_file: /etc/custodia/admin.crt
  client_key_file: /etc/custodia/admin.key
  client_ca_file: /etc/custodia/ca.crt
`)
	resolved, err := defaultAdminTransport(cliConfig{}, configPath)
	if err != nil {
		t.Fatalf("defaultAdminTransport() error = %v", err)
	}
	if resolved.serverURL != "https://custodia.example.internal:8443" || resolved.certFile != "/etc/custodia/admin.crt" || resolved.keyFile != "/etc/custodia/admin.key" || resolved.caFile != "/etc/custodia/ca.crt" {
		t.Fatalf("unexpected resolved transport: %+v", resolved)
	}
}

func TestDefaultAdminTransportKeepsExplicitValues(t *testing.T) {
	explicit := cliConfig{serverURL: "https://explicit.example:8443", certFile: "admin.crt", keyFile: "admin.key", caFile: "ca.crt"}
	resolved, err := defaultAdminTransport(explicit, filepath.Join(t.TempDir(), "missing.yaml"))
	if err != nil {
		t.Fatalf("defaultAdminTransport() error = %v", err)
	}
	if resolved != explicit {
		t.Fatalf("explicit transport changed: %+v", resolved)
	}
}

func TestDefaultAdminTransportRequiresUsableDefaults(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "custodia-server.yaml")
	writeAdminTestFile(t, configPath, `profile: lite
server:
  api_addr: ":8443"
`)
	err := func() error {
		_, err := defaultAdminTransport(cliConfig{}, configPath)
		return err
	}()
	if err == nil || !strings.Contains(err.Error(), "server.url is required") {
		t.Fatalf("expected missing server.url error, got: %v", err)
	}
}

func TestRunWebTOTPConfigureWritesConfig(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "custodia-server.yaml")
	if err := os.WriteFile(configPath, []byte("server:\n  api_addr: ':8443'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runWebTOTPConfigure([]string{"--config", configPath, "--issuer", "Custodia", "--account", "admin"}, &out); err != nil {
		t.Fatalf("runWebTOTPConfigure() error = %v", err)
	}
	body, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"web_totp_secret:", "web_session_secret:"} {
		if !strings.Contains(string(body), want) {
			t.Fatalf("config does not contain %s: %s", want, string(body))
		}
	}
	if !strings.Contains(out.String(), "TOTP secret:") || !strings.Contains(out.String(), "Provisioning URI:") {
		t.Fatalf("unexpected configure output: %s", out.String())
	}
	if err := runWebTOTPConfigure([]string{"--config", configPath}, io.Discard); err == nil {
		t.Fatal("expected duplicate web secret error")
	}
}

func TestRunClientSignCSRValidatesArgsBeforeNetwork(t *testing.T) {
	if err := runClientSignCSR(&cliConfig{}, []string{"--client-id", "client bad", "--csr-file", "client.csr", "--certificate-out", "client.crt"}); err == nil {
		t.Fatal("expected invalid client id error")
	}
	if err := runClientSignCSR(&cliConfig{}, []string{"--client-id", "client_alice", "--certificate-out", "client.crt"}); err == nil {
		t.Fatal("expected missing csr-file error")
	}
	if err := runClientSignCSR(&cliConfig{}, []string{"--client-id", "client_alice", "--csr-file", "client.csr", "--certificate-out", "client.crt", "--ttl-hours", "-1"}); err == nil {
		t.Fatal("expected invalid ttl error")
	}
}
