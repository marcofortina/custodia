package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"custodia/internal/auditarchive"
	"custodia/internal/auditartifact"
	"custodia/internal/audits3shipper"
	"custodia/internal/auditshipper"
	"custodia/internal/build"
	"custodia/internal/certutil"
	"custodia/internal/model"
	"custodia/internal/mtls"
	"custodia/internal/productioncheck"
	"custodia/internal/signing"
)

type cliConfig struct {
	serverURL string
	certFile  string
	keyFile   string
	caFile    string
}

func main() {
	cfg := cliConfig{}
	flags := flag.NewFlagSet("vault-admin", flag.ExitOnError)
	flags.StringVar(&cfg.serverURL, "server-url", env("CUSTODIA_SERVER_URL", "https://localhost:8443"), "Custodia API URL")
	flags.StringVar(&cfg.certFile, "cert", env("CUSTODIA_CLIENT_CERT_FILE", ""), "mTLS client certificate")
	flags.StringVar(&cfg.keyFile, "key", env("CUSTODIA_CLIENT_KEY_FILE", ""), "mTLS client key")
	flags.StringVar(&cfg.caFile, "ca", env("CUSTODIA_SERVER_CA_FILE", ""), "server CA certificate")
	_ = flags.Parse(os.Args[1:])
	args := flags.Args()
	if len(args) == 1 && args[0] == "version" {
		info := build.Current()
		fmt.Fprintf(os.Stdout, "%s %s %s\n", info.Version, info.Commit, info.Date)
		return
	}
	if len(args) < 2 {
		usage()
		os.Exit(2)
	}

	var err error
	switch args[0] + " " + args[1] {
	case "status read":
		err = requestJSON(&cfg, http.MethodGet, "/v1/status", nil, os.Stdout)
	case "version server":
		err = requestJSON(&cfg, http.MethodGet, "/v1/version", nil, os.Stdout)
	case "diagnostics read":
		err = requestJSON(&cfg, http.MethodGet, "/v1/diagnostics", nil, os.Stdout)
	case "revocation status":
		err = requestJSON(&cfg, http.MethodGet, "/v1/revocation/status", nil, os.Stdout)
	case "revocation fetch-crl":
		err = runRevocationFetchCRL(&cfg, args[2:])
	case "revocation check-serial":
		err = runRevocationCheckSerial(&cfg, args[2:])
	case "production check":
		err = runProductionCheck(args[2:])
	case "production evidence-check":
		err = runProductionEvidenceCheck(args[2:])
	case "certificate sign":
		err = runCertificateSign(&cfg, args[2:])
	case "client whoami":
		err = requestJSON(&cfg, http.MethodGet, "/v1/me", nil, os.Stdout)
	case "client list":
		err = runClientList(&cfg, args[2:])
	case "client get":
		err = runClientGet(&cfg, args[2:])
	case "client create":
		err = runClientCreate(&cfg, args[2:])
	case "client csr":
		err = runClientCSR(args[2:])
	case "client revoke":
		err = runClientRevoke(&cfg, args[2:])
	case "audit list":
		err = runAuditList(&cfg, args[2:])
	case "audit export":
		err = runAuditExport(&cfg, args[2:])
	case "audit verify":
		err = runAuditVerify(&cfg, args[2:])
	case "audit verify-export":
		err = runAuditVerifyExport(args[2:])
	case "audit archive-export":
		err = runAuditArchiveExport(args[2:])
	case "audit ship-archive":
		err = runAuditShipArchive(args[2:])
	case "audit ship-archive-s3":
		err = runAuditShipArchiveS3(args[2:])
	case "secret versions":
		err = runSecretVersions(&cfg, args[2:])
	case "access list":
		err = runAccessList(&cfg, args[2:])
	case "access requests":
		err = runAccessRequests(&cfg, args[2:])
	case "access grant-request":
		err = runAccessGrantRequest(&cfg, args[2:])
	case "access activate":
		err = runAccessActivate(&cfg, args[2:])
	case "access revoke":
		err = runAccessRevoke(&cfg, args[2:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runProductionCheck(args []string) error {
	cmd := flag.NewFlagSet("production check", flag.ExitOnError)
	envFile := cmd.String("env-file", "", "environment file to validate")
	_ = cmd.Parse(args)
	if *envFile == "" {
		return fmt.Errorf("--env-file is required")
	}
	env, err := readEnvFile(*envFile)
	if err != nil {
		return err
	}
	findings := productioncheck.CheckEnvironment(env)
	if len(findings) == 0 {
		fmt.Fprintln(os.Stdout, "production readiness: ok")
		return nil
	}
	for _, finding := range findings {
		fmt.Fprintf(os.Stdout, "%s\t%s\t%s\n", finding.Severity, finding.Code, finding.Message)
	}
	if productioncheck.HasCritical(findings) {
		return fmt.Errorf("production readiness check failed")
	}
	return nil
}

func runProductionEvidenceCheck(args []string) error {
	cmd := flag.NewFlagSet("production evidence-check", flag.ExitOnError)
	envFile := cmd.String("env-file", "", "environment file containing external evidence paths")
	_ = cmd.Parse(args)
	if *envFile == "" {
		return fmt.Errorf("--env-file is required")
	}
	env, err := readEnvFile(*envFile)
	if err != nil {
		return err
	}
	findings := productioncheck.CheckExternalEvidence(env)
	if len(findings) == 0 {
		fmt.Fprintln(os.Stdout, "production external evidence: ok")
		return nil
	}
	for _, finding := range findings {
		fmt.Fprintf(os.Stdout, "%s\t%s\t%s\n", finding.Severity, finding.Code, finding.Message)
	}
	if productioncheck.HasCritical(findings) {
		return fmt.Errorf("production external evidence check failed")
	}
	return nil
}

func readEnvFile(path string) (map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	env := make(map[string]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("invalid env line: %s", line)
		}
		env[strings.TrimSpace(key)] = strings.Trim(strings.TrimSpace(value), `"'`)
	}
	return env, scanner.Err()
}

func runRevocationCheckSerial(cfg *cliConfig, args []string) error {
	cmd := flag.NewFlagSet("revocation check-serial", flag.ExitOnError)
	serialHex := cmd.String("serial-hex", "", "certificate serial number in hexadecimal")
	_ = cmd.Parse(args)
	if strings.TrimSpace(*serialHex) == "" {
		return fmt.Errorf("--serial-hex is required")
	}
	path := "/v1/revocation/serial?serial_hex=" + url.QueryEscape(strings.TrimSpace(*serialHex))
	return requestJSON(cfg, http.MethodGet, path, nil, os.Stdout)
}

func runRevocationFetchCRL(cfg *cliConfig, args []string) error {
	cmd := flag.NewFlagSet("revocation fetch-crl", flag.ExitOnError)
	out := cmd.String("out", "", "path for the downloaded PEM CRL")
	_ = cmd.Parse(args)
	if *out == "" {
		return fmt.Errorf("--out is required")
	}
	file, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = requestRaw(cfg, http.MethodGet, "/v1/crl.pem", nil, file)
	return err
}

func runCABootstrapLocal(args []string) error {
	cmd := flag.NewFlagSet("ca bootstrap-local", flag.ExitOnError)
	outDir := cmd.String("out-dir", "", "directory for generated Lite CA artifacts")
	adminClientID := cmd.String("admin-client-id", "admin", "initial admin client id")
	serverName := cmd.String("server-name", "localhost", "server DNS name or IP address for the TLS certificate")
	passphraseFile := cmd.String("ca-passphrase-file", "", "optional file containing the CA key passphrase")
	generatePassphrase := cmd.Bool("generate-ca-passphrase", false, "generate a CA key passphrase file when --ca-passphrase-file is not provided")
	_ = cmd.Parse(args)
	if strings.TrimSpace(*outDir) == "" {
		return fmt.Errorf("--out-dir is required")
	}
	passphrase, passphrasePath, err := liteCAPassphrase(*outDir, *passphraseFile, *generatePassphrase)
	if err != nil {
		return err
	}
	artifacts, err := certutil.GenerateLiteBootstrap(certutil.LiteBootstrapRequest{AdminClientID: *adminClientID, ServerName: *serverName, Passphrase: passphrase})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*outDir, 0o700); err != nil {
		return err
	}
	files := []struct {
		name string
		data []byte
		perm os.FileMode
	}{
		{"ca.crt", artifacts.CACertPEM, 0o644},
		{"ca.key", artifacts.CAKeyPEM, 0o600},
		{"client-ca.crt", artifacts.CACertPEM, 0o644},
		{"client.crl.pem", artifacts.ClientCRLPEM, 0o644},
		{"server.crt", artifacts.ServerCertPEM, 0o644},
		{"server.key", artifacts.ServerKeyPEM, 0o600},
		{"admin.crt", artifacts.AdminCertPEM, 0o644},
		{"admin.key", artifacts.AdminKeyPEM, 0o600},
		{"config.lite.yaml", artifacts.ConfigYAML, 0o640},
	}
	for _, file := range files {
		if err := writeExclusive(strings.TrimRight(*outDir, "/")+"/"+file.name, file.data, file.perm); err != nil {
			return err
		}
	}
	if *generatePassphrase && strings.TrimSpace(*passphraseFile) == "" {
		if err := writeExclusive(passphrasePath, append(passphrase, '\n'), 0o600); err != nil {
			return err
		}
	}
	fmt.Fprintf(os.Stdout, "wrote Lite bootstrap artifacts to %s\n", *outDir)
	return nil
}

func liteCAPassphrase(outDir, passphraseFile string, generate bool) ([]byte, string, error) {
	passphraseFile = strings.TrimSpace(passphraseFile)
	if passphraseFile != "" {
		payload, err := os.ReadFile(passphraseFile)
		if err != nil {
			return nil, "", err
		}
		return []byte(strings.TrimSpace(string(payload))), passphraseFile, nil
	}
	if !generate {
		return nil, "", nil
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, "", err
	}
	return []byte(base64.RawURLEncoding.EncodeToString(secret)), strings.TrimRight(outDir, "/") + "/ca.pass", nil
}

func runCertificateSign(cfg *cliConfig, args []string) error {
	cmd := flag.NewFlagSet("certificate sign", flag.ExitOnError)
	clientID := cmd.String("client-id", "", "client id bound to the CSR")
	csrFile := cmd.String("csr-file", "", "CSR PEM file to submit to custodia-signer")
	ttlHours := cmd.Int("ttl-hours", 0, "optional certificate TTL in hours")
	_ = cmd.Parse(args)
	if *clientID == "" || *csrFile == "" {
		return fmt.Errorf("--client-id and --csr-file are required")
	}
	if !model.ValidClientID(*clientID) {
		return fmt.Errorf("--client-id is invalid")
	}
	if *ttlHours < 0 {
		return fmt.Errorf("--ttl-hours must be positive when set")
	}
	csrPEM, err := os.ReadFile(*csrFile)
	if err != nil {
		return err
	}
	req := signing.SignClientCertificateRequest{ClientID: *clientID, CSRPem: string(csrPEM), TTLHours: *ttlHours}
	return requestJSON(cfg, http.MethodPost, "/v1/certificates/sign", req, os.Stdout)
}

func runClientCSR(args []string) error {
	cmd := flag.NewFlagSet("client csr", flag.ExitOnError)
	clientID := cmd.String("client-id", "", "client id for the CSR subject")
	privateKeyOut := cmd.String("private-key-out", "", "path for the generated private key PEM")
	csrOut := cmd.String("csr-out", "", "path for the generated CSR PEM")
	_ = cmd.Parse(args)
	if *clientID == "" || *privateKeyOut == "" || *csrOut == "" {
		return fmt.Errorf("--client-id, --private-key-out and --csr-out are required")
	}
	generated, err := certutil.GenerateClientCSR(*clientID)
	if err != nil {
		return err
	}
	if err := writeExclusive(*privateKeyOut, generated.PrivateKeyPEM, 0o600); err != nil {
		return err
	}
	if err := writeExclusive(*csrOut, generated.CSRPem, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "wrote %s and %s\n", *privateKeyOut, *csrOut)
	return nil
}

func writeExclusive(path string, data []byte, perm os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.Write(data)
	return err
}

func runClientList(cfg *cliConfig, args []string) error {
	cmd := flag.NewFlagSet("client list", flag.ExitOnError)
	limit := cmd.Int("limit", 0, "optional maximum clients to return, up to 500")
	active := cmd.String("active", "", "optional active-state filter: true or false")
	_ = cmd.Parse(args)
	query := url.Values{}
	if *limit != 0 {
		if *limit < 0 || *limit > 500 {
			return fmt.Errorf("--limit must be between 1 and 500 when set")
		}
		query.Set("limit", strconv.Itoa(*limit))
	}
	if trimmed := strings.TrimSpace(*active); trimmed != "" {
		normalized := strings.ToLower(trimmed)
		if normalized != "true" && normalized != "false" {
			return fmt.Errorf("--active must be true or false when set")
		}
		query.Set("active", normalized)
	}
	path := "/v1/clients"
	if encoded := query.Encode(); encoded != "" {
		path += "?" + encoded
	}
	return requestJSON(cfg, http.MethodGet, path, nil, os.Stdout)
}

func runClientGet(cfg *cliConfig, args []string) error {
	cmd := flag.NewFlagSet("client get", flag.ExitOnError)
	clientID := cmd.String("client-id", "", "client id to read")
	_ = cmd.Parse(args)
	if *clientID == "" {
		return fmt.Errorf("--client-id is required")
	}
	if !model.ValidClientID(*clientID) {
		return fmt.Errorf("--client-id is invalid")
	}
	return requestJSON(cfg, http.MethodGet, "/v1/clients/"+pathEscape(*clientID), nil, os.Stdout)
}

func runClientCreate(cfg *cliConfig, args []string) error {
	cmd := flag.NewFlagSet("client create", flag.ExitOnError)
	req := model.CreateClientRequest{}
	cmd.StringVar(&req.ClientID, "client-id", "", "client id to register")
	cmd.StringVar(&req.MTLSSubject, "mtls-subject", "", "certificate SAN/CN mapped to the client id")
	_ = cmd.Parse(args)
	if req.ClientID == "" || req.MTLSSubject == "" {
		return fmt.Errorf("--client-id and --mtls-subject are required")
	}
	if !model.ValidClientID(req.ClientID) {
		return fmt.Errorf("--client-id is invalid")
	}
	if !model.ValidMTLSSubject(req.MTLSSubject) {
		return fmt.Errorf("--mtls-subject is invalid")
	}
	return requestJSON(cfg, http.MethodPost, "/v1/clients", req, os.Stdout)
}

func runClientRevoke(cfg *cliConfig, args []string) error {
	cmd := flag.NewFlagSet("client revoke", flag.ExitOnError)
	req := model.RevokeClientRequest{}
	cmd.StringVar(&req.ClientID, "client-id", "", "client id to revoke")
	cmd.StringVar(&req.Reason, "reason", "", "revocation reason")
	_ = cmd.Parse(args)
	if req.ClientID == "" {
		return fmt.Errorf("--client-id is required")
	}
	if !model.ValidClientID(req.ClientID) {
		return fmt.Errorf("--client-id is invalid")
	}
	if !model.ValidRevocationReason(req.Reason) {
		return fmt.Errorf("--reason contains control characters or exceeds %d bytes", model.MaxRevocationReasonLength)
	}
	return requestJSON(cfg, http.MethodPost, "/v1/clients/revoke", req, os.Stdout)
}

func runAuditList(cfg *cliConfig, args []string) error {
	cmd := flag.NewFlagSet("audit list", flag.ExitOnError)
	limit := cmd.Int("limit", 100, "maximum audit events to return, up to 500")
	outcome := cmd.String("outcome", "", "optional outcome filter: success, failure or degraded")
	action := cmd.String("action", "", "optional audit action filter")
	actorClientID := cmd.String("actor-client-id", "", "optional actor client id filter")
	resourceType := cmd.String("resource-type", "", "optional resource type filter")
	resourceID := cmd.String("resource-id", "", "optional resource id filter")
	_ = cmd.Parse(args)
	if *limit <= 0 || *limit > 500 {
		return fmt.Errorf("--limit must be between 1 and 500")
	}
	if err := validateAuditFilterFlags(*outcome, *action, *actorClientID, *resourceType, *resourceID); err != nil {
		return err
	}
	query := url.Values{}
	query.Set("limit", strconv.Itoa(*limit))
	addQueryFilter(query, "outcome", *outcome)
	addQueryFilter(query, "action", *action)
	addQueryFilter(query, "actor_client_id", *actorClientID)
	addQueryFilter(query, "resource_type", *resourceType)
	addQueryFilter(query, "resource_id", *resourceID)
	return requestJSON(cfg, http.MethodGet, "/v1/audit-events?"+query.Encode(), nil, os.Stdout)
}

func runAuditExport(cfg *cliConfig, args []string) error {
	cmd := flag.NewFlagSet("audit export", flag.ExitOnError)
	limit := cmd.Int("limit", 500, "maximum audit events to export as JSONL, up to 500")
	outcome := cmd.String("outcome", "", "optional outcome filter: success, failure or degraded")
	action := cmd.String("action", "", "optional audit action filter")
	actorClientID := cmd.String("actor-client-id", "", "optional actor client id filter")
	resourceType := cmd.String("resource-type", "", "optional resource type filter")
	resourceID := cmd.String("resource-id", "", "optional resource id filter")
	outFile := cmd.String("out-file", "", "optional path to write JSONL export body")
	sha256Out := cmd.String("sha256-out", "", "optional path to write export SHA-256 header")
	eventsOut := cmd.String("events-out", "", "optional path to write exported event count header")
	_ = cmd.Parse(args)
	if *limit <= 0 || *limit > 500 {
		return fmt.Errorf("--limit must be between 1 and 500")
	}
	if err := validateAuditFilterFlags(*outcome, *action, *actorClientID, *resourceType, *resourceID); err != nil {
		return err
	}
	query := url.Values{}
	query.Set("limit", strconv.Itoa(*limit))
	addQueryFilter(query, "outcome", *outcome)
	addQueryFilter(query, "action", *action)
	addQueryFilter(query, "actor_client_id", *actorClientID)
	addQueryFilter(query, "resource_type", *resourceType)
	addQueryFilter(query, "resource_id", *resourceID)
	var body bytes.Buffer
	headers, err := requestRaw(cfg, http.MethodGet, "/v1/audit-events/export?"+query.Encode(), nil, &body)
	if err != nil {
		return err
	}
	return writeAuditExportArtifacts(body.Bytes(), headers, *outFile, *sha256Out, *eventsOut, os.Stdout)
}

func writeAuditExportArtifacts(body []byte, headers http.Header, outFile, sha256Out, eventsOut string, stdout io.Writer) error {
	if outFile != "" {
		if err := os.WriteFile(outFile, body, 0o644); err != nil {
			return err
		}
	} else if stdout != nil {
		if _, err := io.Copy(stdout, bytes.NewReader(body)); err != nil {
			return err
		}
	}
	if sha256Out != "" {
		if err := os.WriteFile(sha256Out, []byte(headers.Get("X-Custodia-Audit-Export-SHA256")+"\n"), 0o644); err != nil {
			return err
		}
	}
	if eventsOut != "" {
		if err := os.WriteFile(eventsOut, []byte(headers.Get("X-Custodia-Audit-Export-Events")+"\n"), 0o644); err != nil {
			return err
		}
	}
	return nil
}

func validateAuditFilterFlags(outcome, action, actorClientID, resourceType, resourceID string) error {
	if trimmed := strings.TrimSpace(outcome); trimmed != "" {
		switch trimmed {
		case "success", "failure", "degraded":
		default:
			return fmt.Errorf("--outcome must be success, failure or degraded when set")
		}
	}
	if trimmed := strings.TrimSpace(action); trimmed != "" && !model.ValidAuditAction(trimmed) {
		return fmt.Errorf("--action is invalid")
	}
	if trimmed := strings.TrimSpace(actorClientID); trimmed != "" && !model.ValidClientID(trimmed) {
		return fmt.Errorf("--actor-client-id is invalid")
	}
	if trimmed := strings.TrimSpace(resourceType); trimmed != "" && !model.ValidAuditResourceType(trimmed) {
		return fmt.Errorf("--resource-type is invalid")
	}
	if trimmed := strings.TrimSpace(resourceID); trimmed != "" && !model.ValidAuditResourceID(trimmed) {
		return fmt.Errorf("--resource-id is invalid")
	}
	return nil
}

func runAuditShipArchiveS3(args []string) error {
	cmd := flag.NewFlagSet("audit ship-archive-s3", flag.ExitOnError)
	archiveDir := cmd.String("archive-dir", "", "verified audit archive bundle directory")
	endpoint := cmd.String("endpoint", env("CUSTODIA_AUDIT_S3_ENDPOINT", ""), "S3-compatible endpoint URL")
	region := cmd.String("region", env("CUSTODIA_AUDIT_S3_REGION", "us-east-1"), "S3 signing region")
	bucket := cmd.String("bucket", env("CUSTODIA_AUDIT_S3_BUCKET", ""), "S3 bucket with Object Lock enabled")
	prefix := cmd.String("prefix", env("CUSTODIA_AUDIT_S3_PREFIX", "custodia/audit"), "S3 object key prefix")
	accessKeyID := cmd.String("access-key-id", env("CUSTODIA_AUDIT_S3_ACCESS_KEY_ID", ""), "S3 access key id")
	secretAccessKey := cmd.String("secret-access-key", env("CUSTODIA_AUDIT_S3_SECRET_ACCESS_KEY", ""), "S3 secret access key")
	objectLockMode := cmd.String("object-lock-mode", env("CUSTODIA_AUDIT_S3_OBJECT_LOCK_MODE", "COMPLIANCE"), "S3 Object Lock mode")
	retainUntil := cmd.String("retain-until", env("CUSTODIA_AUDIT_S3_RETAIN_UNTIL", ""), "RFC3339 retention deadline")
	_ = cmd.Parse(args)
	if *archiveDir == "" || *endpoint == "" || *bucket == "" || *accessKeyID == "" || *secretAccessKey == "" || *retainUntil == "" {
		return fmt.Errorf("--archive-dir, --endpoint, --bucket, --access-key-id, --secret-access-key and --retain-until are required")
	}
	parsedRetainUntil, err := time.Parse(time.RFC3339, *retainUntil)
	if err != nil {
		return fmt.Errorf("--retain-until must be RFC3339: %w", err)
	}
	result, err := audits3shipper.ShipArchive(context.Background(), *archiveDir, audits3shipper.Config{
		Endpoint:        *endpoint,
		Region:          *region,
		Bucket:          *bucket,
		Prefix:          *prefix,
		AccessKeyID:     *accessKeyID,
		SecretAccessKey: *secretAccessKey,
		ObjectLockMode:  *objectLockMode,
		RetainUntil:     parsedRetainUntil,
	})
	if encodeErr := json.NewEncoder(os.Stdout).Encode(result); encodeErr != nil {
		return encodeErr
	}
	return err
}

func runAuditShipArchive(args []string) error {
	cmd := flag.NewFlagSet("audit ship-archive", flag.ExitOnError)
	archiveDir := cmd.String("archive-dir", "", "verified audit archive bundle directory")
	sinkDir := cmd.String("sink-dir", "", "destination sink directory")
	_ = cmd.Parse(args)
	if *archiveDir == "" || *sinkDir == "" {
		return fmt.Errorf("--archive-dir and --sink-dir are required")
	}
	result, err := auditshipper.ShipArchive(*archiveDir, *sinkDir, time.Now().UTC())
	if encodeErr := json.NewEncoder(os.Stdout).Encode(result); encodeErr != nil {
		return encodeErr
	}
	return err
}

func runAuditArchiveExport(args []string) error {
	cmd := flag.NewFlagSet("audit archive-export", flag.ExitOnError)
	bodyFile := cmd.String("file", "", "JSONL audit export file")
	sha256File := cmd.String("sha256-file", "", "file containing expected SHA-256 digest")
	eventsFile := cmd.String("events-file", "", "file containing expected exported event count")
	archiveDir := cmd.String("archive-dir", "", "directory where the verified archive bundle will be written")
	_ = cmd.Parse(args)
	if *bodyFile == "" || *sha256File == "" || *eventsFile == "" || *archiveDir == "" {
		return fmt.Errorf("--file, --sha256-file, --events-file and --archive-dir are required")
	}
	body, err := os.ReadFile(*bodyFile)
	if err != nil {
		return err
	}
	digest, err := os.ReadFile(*sha256File)
	if err != nil {
		return err
	}
	events, err := os.ReadFile(*eventsFile)
	if err != nil {
		return err
	}
	result, err := auditarchive.Archive(body, string(digest), string(events), *archiveDir, time.Now().UTC())
	if encodeErr := json.NewEncoder(os.Stdout).Encode(result); encodeErr != nil {
		return encodeErr
	}
	return err
}

func runAuditVerifyExport(args []string) error {
	cmd := flag.NewFlagSet("audit verify-export", flag.ExitOnError)
	bodyFile := cmd.String("file", "", "JSONL audit export file")
	sha256File := cmd.String("sha256-file", "", "file containing expected SHA-256 digest")
	eventsFile := cmd.String("events-file", "", "file containing expected exported event count")
	_ = cmd.Parse(args)
	if *bodyFile == "" || *sha256File == "" || *eventsFile == "" {
		return fmt.Errorf("--file, --sha256-file and --events-file are required")
	}
	body, err := os.ReadFile(*bodyFile)
	if err != nil {
		return err
	}
	digest, err := os.ReadFile(*sha256File)
	if err != nil {
		return err
	}
	events, err := os.ReadFile(*eventsFile)
	if err != nil {
		return err
	}
	result, err := auditartifact.Verify(body, string(digest), string(events))
	if encodeErr := json.NewEncoder(os.Stdout).Encode(result); encodeErr != nil {
		return encodeErr
	}
	return err
}

func runAuditVerify(cfg *cliConfig, args []string) error {
	cmd := flag.NewFlagSet("audit verify", flag.ExitOnError)
	limit := cmd.Int("limit", 500, "maximum audit events to verify, up to 500")
	_ = cmd.Parse(args)
	if *limit <= 0 || *limit > 500 {
		return fmt.Errorf("--limit must be between 1 and 500")
	}
	return requestJSON(cfg, http.MethodGet, fmt.Sprintf("/v1/audit-events/verify?limit=%d", *limit), nil, os.Stdout)
}

func runSecretVersions(cfg *cliConfig, args []string) error {
	cmd := flag.NewFlagSet("secret versions", flag.ExitOnError)
	secretID := cmd.String("secret-id", "", "secret id")
	limit := cmd.Int("limit", 0, "optional maximum versions to return, up to 500")
	_ = cmd.Parse(args)
	if *secretID == "" {
		return fmt.Errorf("--secret-id is required")
	}
	if !model.ValidUUIDID(*secretID) {
		return fmt.Errorf("--secret-id is invalid")
	}
	query := url.Values{}
	if *limit != 0 {
		if *limit < 0 || *limit > 500 {
			return fmt.Errorf("--limit must be between 1 and 500 when set")
		}
		query.Set("limit", strconv.Itoa(*limit))
	}
	path := "/v1/secrets/" + pathEscape(*secretID) + "/versions"
	if encoded := query.Encode(); encoded != "" {
		path += "?" + encoded
	}
	return requestJSON(cfg, http.MethodGet, path, nil, os.Stdout)
}

func runAccessList(cfg *cliConfig, args []string) error {
	cmd := flag.NewFlagSet("access list", flag.ExitOnError)
	secretID := cmd.String("secret-id", "", "secret id")
	limit := cmd.Int("limit", 0, "optional maximum access rows to return, up to 500")
	_ = cmd.Parse(args)
	if *secretID == "" {
		return fmt.Errorf("--secret-id is required")
	}
	if !model.ValidUUIDID(*secretID) {
		return fmt.Errorf("--secret-id is invalid")
	}
	query := url.Values{}
	if *limit != 0 {
		if *limit < 0 || *limit > 500 {
			return fmt.Errorf("--limit must be between 1 and 500 when set")
		}
		query.Set("limit", strconv.Itoa(*limit))
	}
	path := "/v1/secrets/" + pathEscape(*secretID) + "/access"
	if encoded := query.Encode(); encoded != "" {
		path += "?" + encoded
	}
	return requestJSON(cfg, http.MethodGet, path, nil, os.Stdout)
}

func runAccessRequests(cfg *cliConfig, args []string) error {
	cmd := flag.NewFlagSet("access requests", flag.ExitOnError)
	limit := cmd.Int("limit", 100, "maximum pending grant metadata rows to return, up to 500")
	secretID := cmd.String("secret-id", "", "optional secret id filter")
	status := cmd.String("status", "", "optional status filter: pending, activated, revoked or expired")
	clientID := cmd.String("client-id", "", "optional target client id filter")
	requestedBy := cmd.String("requested-by-client-id", "", "optional requester client id filter")
	_ = cmd.Parse(args)
	if *limit <= 0 || *limit > 500 {
		return fmt.Errorf("--limit must be between 1 and 500")
	}
	if trimmed := strings.TrimSpace(*secretID); trimmed != "" && !model.ValidUUIDID(trimmed) {
		return fmt.Errorf("--secret-id is invalid")
	}
	if trimmed := strings.TrimSpace(*status); trimmed != "" && !model.ValidAccessRequestStatus(trimmed) {
		return fmt.Errorf("--status is invalid")
	}
	if trimmed := strings.TrimSpace(*clientID); trimmed != "" && !model.ValidClientID(trimmed) {
		return fmt.Errorf("--client-id is invalid")
	}
	if trimmed := strings.TrimSpace(*requestedBy); trimmed != "" && !model.ValidClientID(trimmed) {
		return fmt.Errorf("--requested-by-client-id is invalid")
	}
	query := url.Values{}
	query.Set("limit", strconv.Itoa(*limit))
	addQueryFilter(query, "secret_id", *secretID)
	addQueryFilter(query, "status", *status)
	addQueryFilter(query, "client_id", *clientID)
	addQueryFilter(query, "requested_by_client_id", *requestedBy)
	return requestJSON(cfg, http.MethodGet, "/v1/access-requests?"+query.Encode(), nil, os.Stdout)
}

func runAccessGrantRequest(cfg *cliConfig, args []string) error {
	cmd := flag.NewFlagSet("access grant-request", flag.ExitOnError)
	secretID := cmd.String("secret-id", "", "secret id")
	clientID := cmd.String("client-id", "", "client id")
	versionID := cmd.String("version-id", "", "secret version id; defaults to latest active version")
	permissions := cmd.String("permissions", "", "permission bits or names: read, write, share, all")
	expiresAt := cmd.String("expires-at", "", "optional RFC3339 access expiration timestamp")
	_ = cmd.Parse(args)
	if *secretID == "" || *clientID == "" || *permissions == "" {
		return fmt.Errorf("--secret-id, --client-id and --permissions are required")
	}
	if !model.ValidUUIDID(*secretID) {
		return fmt.Errorf("--secret-id is invalid")
	}
	if !model.ValidClientID(*clientID) {
		return fmt.Errorf("--client-id is invalid")
	}
	if !model.ValidOptionalUUIDID(*versionID) {
		return fmt.Errorf("--version-id is invalid")
	}
	bits, err := parsePermissionBits(*permissions)
	if err != nil {
		return err
	}
	parsedExpiresAt, err := parseOptionalRFC3339(*expiresAt)
	if err != nil {
		return err
	}
	req := model.AccessGrantRequest{VersionID: *versionID, TargetClientID: *clientID, Permissions: bits, ExpiresAt: parsedExpiresAt}
	return requestJSON(cfg, http.MethodPost, "/v1/secrets/"+pathEscape(*secretID)+"/access-requests", req, os.Stdout)
}

func runAccessActivate(cfg *cliConfig, args []string) error {
	cmd := flag.NewFlagSet("access activate", flag.ExitOnError)
	secretID := cmd.String("secret-id", "", "secret id")
	clientID := cmd.String("client-id", "", "client id")
	envelopeFile := cmd.String("envelope-file", "", "file containing the base64 opaque envelope generated client-side")
	_ = cmd.Parse(args)
	if *secretID == "" || *clientID == "" || *envelopeFile == "" {
		return fmt.Errorf("--secret-id, --client-id and --envelope-file are required")
	}
	if !model.ValidUUIDID(*secretID) {
		return fmt.Errorf("--secret-id is invalid")
	}
	if !model.ValidClientID(*clientID) {
		return fmt.Errorf("--client-id is invalid")
	}
	envelope, err := os.ReadFile(*envelopeFile)
	if err != nil {
		return err
	}
	req := model.ActivateAccessRequest{Envelope: strings.TrimSpace(string(envelope))}
	path := "/v1/secrets/" + pathEscape(*secretID) + "/access/" + pathEscape(*clientID) + "/activate"
	return requestJSON(cfg, http.MethodPost, path, req, os.Stdout)
}

func runAccessRevoke(cfg *cliConfig, args []string) error {
	cmd := flag.NewFlagSet("access revoke", flag.ExitOnError)
	secretID := cmd.String("secret-id", "", "secret id")
	clientID := cmd.String("client-id", "", "client id")
	_ = cmd.Parse(args)
	if *secretID == "" || *clientID == "" {
		return fmt.Errorf("--secret-id and --client-id are required")
	}
	if !model.ValidUUIDID(*secretID) {
		return fmt.Errorf("--secret-id is invalid")
	}
	if !model.ValidClientID(*clientID) {
		return fmt.Errorf("--client-id is invalid")
	}
	path := "/v1/secrets/" + pathEscape(*secretID) + "/access/" + pathEscape(*clientID)
	return requestJSON(cfg, http.MethodDelete, path, nil, os.Stdout)
}

func addQueryFilter(query url.Values, key string, value string) {
	if strings.TrimSpace(value) != "" {
		query.Set(key, strings.TrimSpace(value))
	}
}

func parseOptionalRFC3339(value string) (*time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return nil, fmt.Errorf("timestamp must be RFC3339: %w", err)
	}
	return &parsed, nil
}

func pathEscape(value string) string {
	return url.PathEscape(value)
}

func parsePermissionBits(value string) (int, error) {
	if value == "" {
		return 0, fmt.Errorf("permissions are required")
	}
	if bits, err := strconv.Atoi(value); err == nil {
		if !model.ValidPermissionBits(bits) {
			return 0, fmt.Errorf("invalid permission bits: %d", bits)
		}
		return bits, nil
	}
	bits := 0
	for _, part := range strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == '+' || r == '|' }) {
		switch strings.ToLower(strings.TrimSpace(part)) {
		case "read":
			bits |= int(model.PermissionRead)
		case "write":
			bits |= int(model.PermissionWrite)
		case "share":
			bits |= int(model.PermissionShare)
		case "all":
			bits |= int(model.PermissionAll)
		case "":
			continue
		default:
			return 0, fmt.Errorf("unknown permission %q", part)
		}
	}
	if !model.ValidPermissionBits(bits) {
		return 0, fmt.Errorf("invalid permission bits: %d", bits)
	}
	return bits, nil
}

func requestJSON(cfg *cliConfig, method, path string, payload any, out io.Writer) error {
	_, err := requestRaw(cfg, method, path, payload, out)
	return err
}

func requestRaw(cfg *cliConfig, method, path string, payload any, out io.Writer) (http.Header, error) {
	client, err := httpClient(cfg)
	if err != nil {
		return nil, err
	}
	var body io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(encoded)
	}
	req, err := http.NewRequest(method, cfg.serverURL+path, body)
	if err != nil {
		return nil, err
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode > 299 {
		responseBody, _ := io.ReadAll(res.Body)
		return nil, fmt.Errorf("request failed: %s: %s", res.Status, string(responseBody))
	}
	if out != nil {
		if _, err := io.Copy(out, res.Body); err != nil {
			return nil, err
		}
	} else {
		_, _ = io.Copy(io.Discard, res.Body)
	}
	return res.Header, nil
}

func httpClient(cfg *cliConfig) (*http.Client, error) {
	if cfg.certFile == "" || cfg.keyFile == "" || cfg.caFile == "" {
		return nil, fmt.Errorf("--cert, --key and --ca are required")
	}
	tlsConfig, err := mtls.ClientTLSConfig(cfg.certFile, cfg.keyFile, cfg.caFile)
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}, nil
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  vault-admin [global flags] status read
  vault-admin [global flags] version server
  vault-admin [global flags] client whoami
  vault-admin [global flags] client list
  vault-admin [global flags] client get --client-id ID
  vault-admin [global flags] client create --client-id ID --mtls-subject SUBJECT
  vault-admin [global flags] client revoke --client-id ID [--reason REASON]
  vault-admin [global flags] audit list [--limit N] [--outcome STATUS] [--action ACTION]
  vault-admin [global flags] audit export [--limit N] [--out-file FILE] [--sha256-out FILE] [--events-out FILE]
  vault-admin [global flags] audit verify [--limit N]
  vault-admin [global flags] secret versions --secret-id ID
  vault-admin [global flags] access list --secret-id ID
  vault-admin [global flags] access requests [--limit N] [--secret-id ID] [--status STATUS]
  vault-admin [global flags] access grant-request --secret-id ID --client-id ID --permissions read[,write,share]
  vault-admin [global flags] access activate --secret-id ID --client-id ID --envelope-file FILE
  vault-admin [global flags] access revoke --secret-id ID --client-id ID

global flags:
  --server-url URL
  --cert FILE
  --key FILE
  --ca FILE`)
}
