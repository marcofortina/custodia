// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"custodia/internal/auditarchive"
	"custodia/internal/auditartifact"
	"custodia/internal/audits3shipper"
	"custodia/internal/auditshipper"
	"custodia/internal/build"
	"custodia/internal/certutil"
	serverconfig "custodia/internal/config"
	"custodia/internal/liteupgrade"
	"custodia/internal/model"
	"custodia/internal/mtls"
	"custodia/internal/productioncheck"
	"custodia/internal/signing"
	"custodia/internal/webauth"
)

// cliConfig keeps transport flags separate from command-specific flags so every
// admin command inherits the same mTLS boundary and timeout behavior.
type cliConfig struct {
	serverURL string
	certFile  string
	keyFile   string
	caFile    string
}

func main() {
	cfg := cliConfig{}
	flags := flag.NewFlagSet("custodia-admin", flag.ExitOnError)
	flags.StringVar(&cfg.serverURL, "server-url", env("CUSTODIA_SERVER_URL", ""), "Custodia API URL")
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
	if len(args) >= 1 && args[0] == "doctor" {
		if err := runDoctor(args[1:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if len(args) < 2 {
		usage()
		os.Exit(2)
	}
	if len(args) >= 3 && args[0] == "web" && args[1] == "totp" && args[2] == "generate" {
		if err := runWebTOTPGenerate(args[3:], os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if len(args) >= 3 && args[0] == "web" && args[1] == "totp" && args[2] == "configure" {
		if err := runWebTOTPConfigure(args[3:], os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	var err error
	switch args[0] + " " + args[1] {
	case "status read":
		err = requestDefaultAdminJSON(&cfg, http.MethodGet, "/v1/status", nil, os.Stdout)
	case "version server":
		err = requestJSON(&cfg, http.MethodGet, "/v1/version", nil, os.Stdout)
	case "diagnostics read":
		err = requestDefaultAdminJSON(&cfg, http.MethodGet, "/v1/diagnostics", nil, os.Stdout)
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
	case "lite upgrade-check":
		err = runLiteUpgradeCheck(args[2:])
	case "migration plan":
		err = runMigrationPlan(args[2:])
	case "certificate sign":
		err = runCertificateSign(&cfg, args[2:])
	case "certificate extract":
		err = runCertificateExtract(args[2:])
	case "certificate bundle":
		err = runCertificateBundle(args[2:])
	case "ca bootstrap-local":
		err = runCABootstrapLocal(args[2:])
	case "client whoami":
		err = requestJSON(&cfg, http.MethodGet, "/v1/me", nil, os.Stdout)
	case "client enrollment":
		err = runClientEnrollment(&cfg, args[2:])
	case "client list":
		err = runClientList(&cfg, args[2:])
	case "client get":
		err = runClientGet(&cfg, args[2:])
	case "client create":
		err = runClientCreate(&cfg, args[2:])
	case "client issue":
		err = runClientIssue(&cfg, args[2:])
	case "client sign-csr":
		err = runClientSignCSR(&cfg, args[2:])
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

// runWebTOTPGenerate creates a first-run TOTP secret without requiring operators
// to hand-roll Base32 encoding in the quickstart.
func runWebTOTPGenerate(args []string, out io.Writer) error {
	cmd := flag.NewFlagSet("web totp generate", flag.ExitOnError)
	issuer := cmd.String("issuer", "Custodia", "TOTP issuer label")
	account := cmd.String("account", "admin", "TOTP account label")
	format := cmd.String("format", "text", "output format: text, yaml or json")
	_ = cmd.Parse(args)

	secret, err := webauth.GenerateTOTPSecret()
	if err != nil {
		return err
	}
	uri, err := webauth.TOTPProvisioningURI(*issuer, *account, secret)
	if err != nil {
		return err
	}

	switch strings.ToLower(strings.TrimSpace(*format)) {
	case "text":
		_, err = fmt.Fprintf(out, "TOTP secret: %s\nProvisioning URI: %s\n\nAdd this to /etc/custodia/custodia-server.yaml:\nweb_totp_secret: \"%s\"\n", secret, uri, secret)
		return err
	case "yaml":
		_, err = fmt.Fprintf(out, "web_totp_secret: \"%s\"\n", secret)
		return err
	case "json":
		payload := map[string]string{
			"account":          strings.TrimSpace(*account),
			"issuer":           strings.TrimSpace(*issuer),
			"provisioning_uri": uri,
			"totp_secret":      secret,
		}
		encoded, err := json.MarshalIndent(payload, "", "  ")
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(out, "%s\n", encoded)
		return err
	default:
		return fmt.Errorf("unsupported --format %q", *format)
	}
}

// runWebTOTPConfigure writes first-run Web MFA material to the server YAML config.
func runWebTOTPConfigure(args []string, out io.Writer) error {
	cmd := flag.NewFlagSet("web totp configure", flag.ExitOnError)
	configPath := cmd.String("config", "/etc/custodia/custodia-server.yaml", "custodia-server YAML config to update")
	issuer := cmd.String("issuer", "Custodia", "TOTP issuer label")
	account := cmd.String("account", "admin", "TOTP account label")
	_ = cmd.Parse(args)

	if strings.TrimSpace(*configPath) == "" {
		return fmt.Errorf("--config is required")
	}
	body, err := os.ReadFile(*configPath)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}
	if serverConfigHasWebSecrets(string(body)) {
		return fmt.Errorf("web_totp_secret or web_session_secret already exists; edit %s instead of appending duplicates", *configPath)
	}
	secret, err := webauth.GenerateTOTPSecret()
	if err != nil {
		return err
	}
	uri, err := webauth.TOTPProvisioningURI(*issuer, *account, secret)
	if err != nil {
		return err
	}
	sessionSecret, err := randomBase64(48)
	if err != nil {
		return err
	}
	appendix := fmt.Sprintf("\nweb_totp_secret: %q\nweb_session_secret: %q\n", secret, sessionSecret)
	file, err := os.OpenFile(*configPath, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return fmt.Errorf("open config for append: %w", err)
	}
	if _, err := file.WriteString(appendix); err != nil {
		_ = file.Close()
		return fmt.Errorf("append web secrets: %w", err)
	}
	if err := file.Close(); err != nil {
		return err
	}
	fmt.Fprintf(out, "web TOTP configured in %s\n", *configPath)
	fmt.Fprintf(out, "TOTP secret: %s\n", secret)
	fmt.Fprintf(out, "Provisioning URI: %s\n", uri)
	fmt.Fprintln(out, "The TOTP secret and provisioning URI are sensitive; do not paste install logs into public issues or chats.")
	if qrOut, err := renderTOTPQRCode(uri); err == nil {
		fmt.Fprintln(out, "\nQR code:")
		fmt.Fprint(out, qrOut)
	} else {
		fmt.Fprintf(out, "Hint: install qrencode to print a terminal QR code (%v).\n", err)
	}
	return nil
}

func serverConfigHasWebSecrets(config string) bool {
	scanner := bufio.NewScanner(strings.NewReader(config))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "web_totp_secret:") || strings.HasPrefix(line, "web_session_secret:") {
			return true
		}
	}
	return false
}

func randomBase64(size int) (string, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf), nil
}

func renderTOTPQRCode(uri string) (string, error) {
	path, err := exec.LookPath("qrencode")
	if err != nil {
		return "", err
	}
	cmd := exec.Command(path, "-t", "ANSIUTF8", uri)
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(output), nil
}

// runProductionCheck intentionally validates environment files offline.
// Production readiness must be reproducible without contacting the running vault.
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

// runProductionEvidenceCheck verifies operator-supplied evidence paths instead of
// trusting configuration flags that merely claim external controls are enabled.
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

func runMigrationPlan(args []string) error {
	cmd := flag.NewFlagSet("migration plan", flag.ExitOnError)
	sourceConfig := cmd.String("source-config", "", "source custodia-server YAML config")
	targetConfig := cmd.String("target-config", "", "target custodia-server YAML config")
	_ = cmd.Parse(args)
	if strings.TrimSpace(*sourceConfig) == "" {
		return fmt.Errorf("--source-config is required")
	}
	if strings.TrimSpace(*targetConfig) == "" {
		return fmt.Errorf("--target-config is required")
	}
	source, err := serverconfig.LoadFile(*sourceConfig)
	if err != nil {
		return fmt.Errorf("load source config: %w", err)
	}
	target, err := serverconfig.LoadFile(*targetConfig)
	if err != nil {
		return fmt.Errorf("load target config: %w", err)
	}
	direction := migrationDirection(source, target)
	switch direction {
	case "lite-to-full":
		findings := liteupgrade.Check(configToUpgradeEnv(source), configToUpgradeEnv(target))
		if len(findings) == 0 {
			fmt.Fprintln(os.Stdout, "lite to full migration plan: ok")
			return nil
		}
		for _, finding := range findings {
			fmt.Fprintf(os.Stdout, "%s\t%s\t%s\n", finding.Severity, finding.Code, finding.Message)
		}
		if productioncheck.HasCritical(findings) {
			return fmt.Errorf("lite to full migration plan failed")
		}
		return nil
	case "full-to-lite":
		fmt.Fprintln(os.Stdout, "warning\tfull_to_lite_manual\tFull to Lite is a downgrade path and cannot be automated safely; plan explicit data export, reduced availability and signer/key-provider changes.")
		fmt.Fprintln(os.Stdout, "warning\tfull_to_lite_store\tTarget Lite config must use SQLite and only data that fits single-node operation should be imported.")
		return nil
	default:
		return fmt.Errorf("unsupported migration direction: source profile=%s store=%s target profile=%s store=%s", source.Profile, source.StoreBackend, target.Profile, target.StoreBackend)
	}
}

func migrationDirection(source, target serverconfig.Config) string {
	sourceProfile := strings.ToLower(strings.TrimSpace(source.Profile))
	sourceStore := strings.ToLower(strings.TrimSpace(source.StoreBackend))
	targetProfile := strings.ToLower(strings.TrimSpace(target.Profile))
	targetStore := strings.ToLower(strings.TrimSpace(target.StoreBackend))
	if (sourceProfile == serverconfig.ProfileLite || sourceProfile == serverconfig.ProfileCustom) && sourceStore == "sqlite" && (targetProfile == serverconfig.ProfileFull || targetProfile == serverconfig.ProfileCustom) && targetStore == "postgres" {
		return "lite-to-full"
	}
	if (sourceProfile == serverconfig.ProfileFull || sourceProfile == serverconfig.ProfileCustom) && sourceStore == "postgres" && (targetProfile == serverconfig.ProfileLite || targetProfile == serverconfig.ProfileCustom) && targetStore == "sqlite" {
		return "full-to-lite"
	}
	return ""
}

func configToUpgradeEnv(cfg serverconfig.Config) map[string]string {
	return map[string]string{
		"CUSTODIA_PROFILE":             cfg.Profile,
		"CUSTODIA_STORE_BACKEND":       cfg.StoreBackend,
		"CUSTODIA_DATABASE_URL":        cfg.DatabaseURL,
		"CUSTODIA_RATE_LIMIT_BACKEND":  cfg.RateLimitBackend,
		"CUSTODIA_VALKEY_URL":          cfg.ValkeyURL,
		"CUSTODIA_SIGNER_KEY_PROVIDER": cfg.SignerKeyProvider,
		"CUSTODIA_AUDIT_SHIPMENT_SINK": cfg.AuditShipmentSink,
		"CUSTODIA_DATABASE_HA_TARGET":  cfg.DatabaseHATarget,
	}
}

func runLiteUpgradeCheck(args []string) error {
	cmd := flag.NewFlagSet("lite upgrade-check", flag.ExitOnError)
	liteEnvFile := cmd.String("lite-env-file", "", "source Lite environment file")
	fullEnvFile := cmd.String("full-env-file", "", "target Full environment file")
	_ = cmd.Parse(args)
	if *liteEnvFile == "" {
		return fmt.Errorf("--lite-env-file is required")
	}
	if *fullEnvFile == "" {
		return fmt.Errorf("--full-env-file is required")
	}
	liteEnv, err := readEnvFile(*liteEnvFile)
	if err != nil {
		return err
	}
	fullEnv, err := readEnvFile(*fullEnvFile)
	if err != nil {
		return err
	}
	findings := liteupgrade.Check(liteEnv, fullEnv)
	if len(findings) == 0 {
		fmt.Fprintln(os.Stdout, "lite to full upgrade readiness: ok")
		return nil
	}
	for _, finding := range findings {
		fmt.Fprintf(os.Stdout, "%s\t%s\t%s\n", finding.Severity, finding.Code, finding.Message)
	}
	if productioncheck.HasCritical(findings) {
		return fmt.Errorf("lite to full upgrade readiness check failed")
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
	_, requestErr := requestRaw(cfg, http.MethodGet, "/v1/crl.pem", nil, file)
	closeErr := file.Close()
	if requestErr != nil {
		return requestErr
	}
	return closeErr
}

func runCABootstrapLocal(args []string) error {
	cmd := flag.NewFlagSet("ca bootstrap-local", flag.ExitOnError)
	outDir := cmd.String("out-dir", "", "directory for generated Lite CA artifacts")
	adminClientID := cmd.String("admin-client-id", "admin", "initial admin client id")
	serverName := cmd.String("server-name", "localhost", "server DNS name or IP address for the TLS certificate SANs")
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
		{"custodia-server.yaml", artifacts.ConfigYAML, 0o640},
		{"custodia-signer.yaml", artifacts.SignerConfigYAML, 0o640},
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
	fmt.Fprintf(os.Stdout, "wrote bootstrap artifacts to %s\n", *outDir)
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

func runCertificateExtract(args []string) error {
	cmd := flag.NewFlagSet("certificate extract", flag.ExitOnError)
	input := cmd.String("input", "", "signer JSON response file, or - for stdin")
	certificateOut := cmd.String("certificate-out", "", "path for the extracted client certificate PEM")
	_ = cmd.Parse(args)
	if *input == "" || *certificateOut == "" {
		return fmt.Errorf("--input and --certificate-out are required")
	}
	payload, err := readFileOrStdin(*input)
	if err != nil {
		return err
	}
	var response signing.SignClientCertificateResponse
	if err := json.Unmarshal(payload, &response); err != nil {
		return fmt.Errorf("invalid signer JSON: %w", err)
	}
	certificatePEM, err := normalizeClientCertificatePEM(response.CertificatePEM)
	if err != nil {
		return err
	}
	return writeExclusive(*certificateOut, certificatePEM, 0o644)
}

func runCertificateBundle(args []string) error {
	cmd := flag.NewFlagSet("certificate bundle", flag.ExitOnError)
	certificateFile := cmd.String("certificate", "", "client certificate PEM file")
	privateKeyFile := cmd.String("private-key", "", "client private key PEM file generated locally")
	caFile := cmd.String("ca", "", "CA certificate PEM file trusted by the client")
	outFile := cmd.String("out", "", "zip bundle output path")
	_ = cmd.Parse(args)
	if *certificateFile == "" || *privateKeyFile == "" || *caFile == "" || *outFile == "" {
		return fmt.Errorf("--certificate, --private-key, --ca and --out are required")
	}

	certificatePEM, err := readAndNormalizeClientCertificate(*certificateFile)
	if err != nil {
		return err
	}
	privateKeyPEM, err := readAndNormalizePrivateKey(*privateKeyFile)
	if err != nil {
		return err
	}
	caPEM, err := readAndNormalizeCACertificate(*caFile)
	if err != nil {
		return err
	}

	entries := []bundleEntry{
		{name: "client.crt", data: certificatePEM, mode: 0o644},
		{name: "client.key", data: privateKeyPEM, mode: 0o600},
		{name: "ca.crt", data: caPEM, mode: 0o644},
		{name: "README.txt", data: []byte(certificateBundleReadme), mode: 0o644},
	}
	return writeCertificateBundle(*outFile, entries)
}

type bundleEntry struct {
	name string
	data []byte
	mode os.FileMode
}

const certificateBundleReadme = `Custodia client mTLS bundle

Files:
- client.crt: client mTLS certificate signed by the Custodia CA.
- client.key: client mTLS private key generated locally by the operator.
- ca.crt: CA certificate used to verify Custodia server/signer endpoints.

Security notes:
- Protect this archive because it contains client.key.
- Do not upload this archive to Custodia or to the Web Console.
- Application encryption keys are separate from these mTLS transport files.
`

func readAndNormalizeClientCertificate(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return normalizeClientCertificatePEM(string(data))
}

func readAndNormalizePrivateKey(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	payload := strings.TrimSpace(string(data))
	if payload == "" {
		return nil, fmt.Errorf("private key PEM is empty")
	}
	block, rest := pem.Decode([]byte(payload))
	if block == nil {
		return nil, fmt.Errorf("private key PEM must contain a PEM private key")
	}
	if strings.TrimSpace(string(rest)) != "" {
		return nil, fmt.Errorf("private key PEM must contain exactly one PEM block")
	}
	switch block.Type {
	case "PRIVATE KEY":
		if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
			return nil, fmt.Errorf("private key PEM is not a valid PKCS#8 private key: %w", err)
		}
	case "EC PRIVATE KEY":
		if _, err := x509.ParseECPrivateKey(block.Bytes); err != nil {
			return nil, fmt.Errorf("private key PEM is not a valid EC private key: %w", err)
		}
	case "RSA PRIVATE KEY":
		if _, err := x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
			return nil, fmt.Errorf("private key PEM is not a valid RSA private key: %w", err)
		}
	default:
		return nil, fmt.Errorf("private key PEM block type %q is not supported", block.Type)
	}
	return append([]byte(payload), '\n'), nil
}

func readAndNormalizeCACertificate(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	payload := strings.TrimSpace(string(data))
	if payload == "" {
		return nil, fmt.Errorf("CA certificate PEM is empty")
	}
	block, rest := pem.Decode([]byte(payload))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("CA certificate PEM must contain a PEM certificate")
	}
	if strings.TrimSpace(string(rest)) != "" {
		return nil, fmt.Errorf("CA certificate PEM must contain exactly one PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("CA certificate PEM is not a valid certificate: %w", err)
	}
	if !cert.IsCA {
		return nil, fmt.Errorf("CA certificate PEM is not a CA certificate")
	}
	return append([]byte(payload), '\n'), nil
}

func writeCertificateBundle(path string, entries []bundleEntry) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	zipWriter := zip.NewWriter(file)
	for _, entry := range entries {
		header := &zip.FileHeader{Name: entry.name, Method: zip.Deflate}
		header.SetMode(entry.mode)
		writer, err := zipWriter.CreateHeader(header)
		if err != nil {
			_ = zipWriter.Close()
			_ = file.Close()
			return err
		}
		if _, err := writer.Write(entry.data); err != nil {
			_ = zipWriter.Close()
			_ = file.Close()
			return err
		}
	}
	if err := zipWriter.Close(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func readFileOrStdin(path string) ([]byte, error) {
	if strings.TrimSpace(path) == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

func normalizeClientCertificatePEM(payload string) ([]byte, error) {
	payload = strings.TrimSpace(payload)
	if payload == "" {
		return nil, fmt.Errorf("signer JSON does not contain certificate_pem")
	}
	block, rest := pem.Decode([]byte(payload))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("certificate_pem must contain a PEM certificate")
	}
	if strings.TrimSpace(string(rest)) != "" {
		return nil, fmt.Errorf("certificate_pem must contain exactly one PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("certificate_pem is not a valid certificate: %w", err)
	}
	clientAuth := false
	for _, usage := range cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth {
			clientAuth = true
			break
		}
	}
	if !clientAuth {
		return nil, fmt.Errorf("certificate_pem is not a client-auth certificate")
	}
	return append([]byte(payload), '\n'), nil
}

func runClientIssue(cfg *cliConfig, args []string) error {
	cmd := flag.NewFlagSet("client issue", flag.ExitOnError)
	clientID := cmd.String("client-id", "", "client id to register and issue")
	mtlsSubject := cmd.String("mtls-subject", "", "certificate SAN/CN mapped to the client id; defaults to client id")
	outDir := cmd.String("out-dir", "", "output directory for key, CSR, certificate and bundle")
	vaultURL := cmd.String("vault-url", "", "Custodia vault API URL; defaults to global --server-url")
	signerURL := cmd.String("signer-url", env("CUSTODIA_SIGNER_URL", "https://localhost:9444"), "custodia-signer URL")
	ttlHours := cmd.Int("ttl-hours", 0, "optional certificate TTL in hours")
	_ = cmd.Parse(args)
	id := strings.TrimSpace(*clientID)
	if id == "" || strings.TrimSpace(*outDir) == "" {
		return fmt.Errorf("--client-id and --out-dir are required")
	}
	if !model.ValidClientID(id) {
		return fmt.Errorf("--client-id is invalid")
	}
	subject := strings.TrimSpace(*mtlsSubject)
	if subject == "" {
		subject = id
	}
	if !model.ValidMTLSSubject(subject) {
		return fmt.Errorf("--mtls-subject is invalid")
	}
	if *ttlHours < 0 {
		return fmt.Errorf("--ttl-hours must be positive when set")
	}
	if strings.TrimSpace(*signerURL) == "" {
		return fmt.Errorf("--signer-url is required")
	}
	paths := clientIssueOutputPaths(*outDir, id)
	if err := ensureClientIssueOutputsAvailable(paths); err != nil {
		return err
	}
	generated, err := certutil.GenerateClientCSR(id)
	if err != nil {
		return err
	}
	vaultCfg := *cfg
	if strings.TrimSpace(*vaultURL) != "" {
		vaultCfg.serverURL = strings.TrimSpace(*vaultURL)
	}
	signerCfg := *cfg
	signerCfg.serverURL = strings.TrimSpace(*signerURL)
	if err := requestJSON(&vaultCfg, http.MethodPost, "/v1/clients", model.CreateClientRequest{ClientID: id, MTLSSubject: subject}, io.Discard); err != nil {
		return fmt.Errorf("register client metadata: %w", err)
	}
	if err := writeExclusive(paths.privateKey, generated.PrivateKeyPEM, 0o600); err != nil {
		return err
	}
	if err := writeExclusive(paths.csr, generated.CSRPem, 0o644); err != nil {
		return err
	}
	signReq := signing.SignClientCertificateRequest{ClientID: id, CSRPem: string(generated.CSRPem), TTLHours: *ttlHours}
	var signBody bytes.Buffer
	if err := requestJSON(&signerCfg, http.MethodPost, "/v1/certificates/sign", signReq, &signBody); err != nil {
		return fmt.Errorf("sign client certificate: %w", err)
	}
	if err := writeExclusive(paths.signerJSON, signBody.Bytes(), 0o600); err != nil {
		return err
	}
	var signResponse signing.SignClientCertificateResponse
	if err := json.Unmarshal(signBody.Bytes(), &signResponse); err != nil {
		return fmt.Errorf("invalid signer JSON: %w", err)
	}
	certificatePEM, err := normalizeClientCertificatePEM(signResponse.CertificatePEM)
	if err != nil {
		return err
	}
	if err := writeExclusive(paths.certificate, certificatePEM, 0o644); err != nil {
		return err
	}
	if err := runCertificateBundle([]string{"--certificate", paths.certificate, "--private-key", paths.privateKey, "--ca", cfg.caFile, "--out", paths.bundle}); err != nil {
		return fmt.Errorf("bundle issued client material: %w", err)
	}
	fmt.Fprintf(os.Stdout, "issued %s into %s\n", id, *outDir)
	return nil
}

type clientIssuePaths struct {
	outDir      string
	privateKey  string
	csr         string
	signerJSON  string
	certificate string
	bundle      string
}

func clientIssueOutputPaths(outDir, clientID string) clientIssuePaths {
	prefix := safeClientIssueFilePrefix(clientID)
	return clientIssuePaths{
		outDir:      outDir,
		privateKey:  filepath.Join(outDir, prefix+".key"),
		csr:         filepath.Join(outDir, prefix+".csr"),
		signerJSON:  filepath.Join(outDir, prefix+".sign.json"),
		certificate: filepath.Join(outDir, prefix+".crt"),
		bundle:      filepath.Join(outDir, prefix+"-mtls.zip"),
	}
}

func safeClientIssueFilePrefix(clientID string) string {
	var b strings.Builder
	for _, r := range clientID {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			b.WriteRune(r)
			continue
		}
		b.WriteByte('_')
	}
	return b.String()
}

func ensureClientIssueOutputsAvailable(paths clientIssuePaths) error {
	if err := os.MkdirAll(paths.outDir, 0o700); err != nil {
		return err
	}
	for _, path := range []string{paths.privateKey, paths.csr, paths.signerJSON, paths.certificate, paths.bundle} {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("output already exists: %s", path)
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func runClientSignCSR(cfg *cliConfig, args []string) error {
	cmd := flag.NewFlagSet("client sign-csr", flag.ExitOnError)
	clientID := cmd.String("client-id", "", "client id to register and sign")
	mtlsSubject := cmd.String("mtls-subject", "", "certificate SAN/CN mapped to the client id; defaults to client id")
	csrFile := cmd.String("csr-file", "", "client-generated CSR PEM file")
	certificateOut := cmd.String("certificate-out", "", "path for signed client certificate PEM")
	vaultURL := cmd.String("vault-url", "", "Custodia vault API URL; defaults to global --server-url")
	signerURL := cmd.String("signer-url", env("CUSTODIA_SIGNER_URL", "https://localhost:9444"), "custodia-signer URL")
	ttlHours := cmd.Int("ttl-hours", 0, "optional certificate TTL in hours")
	_ = cmd.Parse(args)
	id := strings.TrimSpace(*clientID)
	if id == "" || strings.TrimSpace(*csrFile) == "" || strings.TrimSpace(*certificateOut) == "" {
		return fmt.Errorf("--client-id, --csr-file and --certificate-out are required")
	}
	if !model.ValidClientID(id) {
		return fmt.Errorf("--client-id is invalid")
	}
	subject := strings.TrimSpace(*mtlsSubject)
	if subject == "" {
		subject = id
	}
	if !model.ValidMTLSSubject(subject) {
		return fmt.Errorf("--mtls-subject is invalid")
	}
	if *ttlHours < 0 {
		return fmt.Errorf("--ttl-hours must be positive when set")
	}
	csrPEM, err := os.ReadFile(*csrFile)
	if err != nil {
		return err
	}
	vaultCfg := *cfg
	if strings.TrimSpace(*vaultURL) != "" {
		vaultCfg.serverURL = strings.TrimSpace(*vaultURL)
	}
	signerCfg := *cfg
	signerCfg.serverURL = strings.TrimSpace(*signerURL)
	if strings.TrimSpace(signerCfg.serverURL) == "" {
		return fmt.Errorf("--signer-url is required")
	}
	if err := requestJSON(&vaultCfg, http.MethodPost, "/v1/clients", model.CreateClientRequest{ClientID: id, MTLSSubject: subject}, io.Discard); err != nil {
		return fmt.Errorf("register client metadata: %w", err)
	}
	signReq := signing.SignClientCertificateRequest{ClientID: id, CSRPem: string(csrPEM), TTLHours: *ttlHours}
	var signBody bytes.Buffer
	if err := requestJSON(&signerCfg, http.MethodPost, "/v1/certificates/sign", signReq, &signBody); err != nil {
		return fmt.Errorf("sign client certificate: %w", err)
	}
	var signResponse signing.SignClientCertificateResponse
	if err := json.Unmarshal(signBody.Bytes(), &signResponse); err != nil {
		return fmt.Errorf("invalid signer JSON: %w", err)
	}
	certificatePEM, err := normalizeClientCertificatePEM(signResponse.CertificatePEM)
	if err != nil {
		return err
	}
	if err := writeExclusive(*certificateOut, certificatePEM, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "signed %s into %s\n", id, *certificateOut)
	return nil
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
	_, writeErr := file.Write(data)
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}

func runClientEnrollment(cfg *cliConfig, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("missing client enrollment subcommand")
	}
	switch strings.TrimSpace(args[0]) {
	case "create":
		return runClientEnrollmentCreate(cfg, args[1:])
	default:
		return fmt.Errorf("unknown client enrollment subcommand: %s", args[0])
	}
}

func runClientEnrollmentCreate(cfg *cliConfig, args []string) error {
	cmd := flag.NewFlagSet("client enrollment create", flag.ExitOnError)
	configFile := cmd.String("config", "/etc/custodia/custodia-server.yaml", "Custodia server config file")
	ttl := cmd.Duration("ttl", 15*time.Minute, "enrollment token TTL")
	_ = cmd.Parse(args)
	if *ttl <= 0 {
		return fmt.Errorf("--ttl must be positive")
	}
	serverCfg, err := serverconfig.LoadFile(*configFile)
	if err != nil {
		return fmt.Errorf("load server config: %w", err)
	}
	requestCfg := *cfg
	requestCfg.serverURL = strings.TrimSpace(serverCfg.ServerURL)
	if requestCfg.serverURL == "" {
		return fmt.Errorf("server_url is required in %s", *configFile)
	}
	if strings.TrimSpace(requestCfg.certFile) == "" {
		requestCfg.certFile = "/etc/custodia/admin.crt"
	}
	if strings.TrimSpace(requestCfg.keyFile) == "" {
		requestCfg.keyFile = "/etc/custodia/admin.key"
	}
	if strings.TrimSpace(requestCfg.caFile) == "" {
		requestCfg.caFile = "/etc/custodia/ca.crt"
	}
	req := model.ClientEnrollmentCreateRequest{TTLSeconds: int(ttl.Seconds())}
	return requestJSON(&requestCfg, http.MethodPost, "/v1/client-enrollments", req, os.Stdout)
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

// runAuditVerifyExport binds the exported body to the digest and event-count
// headers returned by the API. This catches truncated or swapped audit artifacts.
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
	namespace := cmd.String("namespace", model.DefaultSecretNamespace, "secret namespace")
	key := cmd.String("key", "", "secret key")
	limit := cmd.Int("limit", 0, "optional maximum versions to return, up to 500")
	_ = cmd.Parse(args)
	query, err := secretKeyspaceQuery(*namespace, *key)
	if err != nil {
		return err
	}
	if *limit != 0 {
		if *limit < 0 || *limit > 500 {
			return fmt.Errorf("--limit must be between 1 and 500 when set")
		}
		query.Set("limit", strconv.Itoa(*limit))
	}
	return requestJSON(cfg, http.MethodGet, "/v1/secrets/by-key/versions?"+query.Encode(), nil, os.Stdout)
}

func runAccessList(cfg *cliConfig, args []string) error {
	cmd := flag.NewFlagSet("access list", flag.ExitOnError)
	namespace := cmd.String("namespace", model.DefaultSecretNamespace, "secret namespace")
	key := cmd.String("key", "", "secret key")
	limit := cmd.Int("limit", 0, "optional maximum access rows to return, up to 500")
	_ = cmd.Parse(args)
	query, err := secretKeyspaceQuery(*namespace, *key)
	if err != nil {
		return err
	}
	if *limit != 0 {
		if *limit < 0 || *limit > 500 {
			return fmt.Errorf("--limit must be between 1 and 500 when set")
		}
		query.Set("limit", strconv.Itoa(*limit))
	}
	return requestJSON(cfg, http.MethodGet, "/v1/secrets/by-key/access?"+query.Encode(), nil, os.Stdout)
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
	namespace := cmd.String("namespace", model.DefaultSecretNamespace, "secret namespace")
	key := cmd.String("key", "", "secret key")
	clientID := cmd.String("client-id", "", "client id")
	versionID := cmd.String("version-id", "", "secret version id; defaults to latest active version")
	permissions := cmd.String("permissions", "", "permission bits or names: read, write, share, all")
	expiresAt := cmd.String("expires-at", "", "optional RFC3339 access expiration timestamp")
	_ = cmd.Parse(args)
	query, err := secretKeyspaceQuery(*namespace, *key)
	if err != nil {
		return err
	}
	if *clientID == "" || *permissions == "" {
		return fmt.Errorf("--key, --client-id and --permissions are required")
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
	return requestJSON(cfg, http.MethodPost, "/v1/secrets/by-key/access-requests?"+query.Encode(), req, os.Stdout)
}

func runAccessActivate(cfg *cliConfig, args []string) error {
	cmd := flag.NewFlagSet("access activate", flag.ExitOnError)
	namespace := cmd.String("namespace", model.DefaultSecretNamespace, "secret namespace")
	key := cmd.String("key", "", "secret key")
	clientID := cmd.String("client-id", "", "client id")
	envelopeFile := cmd.String("envelope-file", "", "file containing the base64 opaque envelope generated client-side")
	_ = cmd.Parse(args)
	query, err := secretKeyspaceQuery(*namespace, *key)
	if err != nil {
		return err
	}
	if *clientID == "" || *envelopeFile == "" {
		return fmt.Errorf("--key, --client-id and --envelope-file are required")
	}
	if !model.ValidClientID(*clientID) {
		return fmt.Errorf("--client-id is invalid")
	}
	envelope, err := os.ReadFile(*envelopeFile)
	if err != nil {
		return err
	}
	req := model.ActivateAccessRequest{Envelope: strings.TrimSpace(string(envelope))}
	path := "/v1/secrets/by-key/access/" + pathEscape(*clientID) + "/activate?" + query.Encode()
	return requestJSON(cfg, http.MethodPost, path, req, os.Stdout)
}

func runAccessRevoke(cfg *cliConfig, args []string) error {
	cmd := flag.NewFlagSet("access revoke", flag.ExitOnError)
	namespace := cmd.String("namespace", model.DefaultSecretNamespace, "secret namespace")
	key := cmd.String("key", "", "secret key")
	clientID := cmd.String("client-id", "", "client id")
	_ = cmd.Parse(args)
	query, err := secretKeyspaceQuery(*namespace, *key)
	if err != nil {
		return err
	}
	if *clientID == "" {
		return fmt.Errorf("--key and --client-id are required")
	}
	if !model.ValidClientID(*clientID) {
		return fmt.Errorf("--client-id is invalid")
	}
	path := "/v1/secrets/by-key/access/" + pathEscape(*clientID) + "?" + query.Encode()
	return requestJSON(cfg, http.MethodDelete, path, nil, os.Stdout)
}

func secretKeyspaceQuery(namespace, key string) (url.Values, error) {
	namespace = model.NormalizeSecretNamespace(namespace)
	key = model.NormalizeSecretKey(key)
	if !model.ValidSecretNamespace(namespace) {
		return nil, fmt.Errorf("--namespace is invalid")
	}
	if !model.ValidSecretKey(key) {
		return nil, fmt.Errorf("--key is required")
	}
	query := url.Values{}
	query.Set("namespace", namespace)
	query.Set("key", key)
	return query, nil
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

const defaultAdminServerConfigFile = "/etc/custodia/custodia-server.yaml"

func requestDefaultAdminJSON(cfg *cliConfig, method, path string, payload any, out io.Writer) error {
	resolved, err := defaultAdminTransport(*cfg, defaultAdminServerConfigFile)
	if err != nil {
		return err
	}
	return requestJSON(&resolved, method, path, payload, out)
}

func defaultAdminTransport(cfg cliConfig, configFile string) (cliConfig, error) {
	if transportComplete(cfg) {
		return cfg, nil
	}
	serverCfg, err := serverconfig.LoadFile(configFile)
	if err != nil {
		return cfg, fmt.Errorf("load default admin transport from %s: %w", configFile, err)
	}
	if strings.TrimSpace(cfg.serverURL) == "" {
		cfg.serverURL = strings.TrimSpace(serverCfg.ServerURL)
	}
	if strings.TrimSpace(cfg.certFile) == "" {
		cfg.certFile = strings.TrimSpace(serverCfg.SignerClientCertFile)
	}
	if strings.TrimSpace(cfg.keyFile) == "" {
		cfg.keyFile = strings.TrimSpace(serverCfg.SignerClientKeyFile)
	}
	if strings.TrimSpace(cfg.caFile) == "" {
		cfg.caFile = strings.TrimSpace(serverCfg.SignerClientCAFile)
	}
	if strings.TrimSpace(cfg.serverURL) == "" {
		return cfg, fmt.Errorf("server.url is required in %s or provide --server-url", configFile)
	}
	if strings.TrimSpace(cfg.certFile) == "" || strings.TrimSpace(cfg.keyFile) == "" || strings.TrimSpace(cfg.caFile) == "" {
		return cfg, fmt.Errorf("signer client_cert_file, client_key_file and client_ca_file are required in %s or provide --cert, --key and --ca", configFile)
	}
	return cfg, nil
}

func transportComplete(cfg cliConfig) bool {
	return strings.TrimSpace(cfg.serverURL) != "" && strings.TrimSpace(cfg.certFile) != "" && strings.TrimSpace(cfg.keyFile) != "" && strings.TrimSpace(cfg.caFile) != ""
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
  custodia-admin [global flags] status read
  custodia-admin [global flags] version server
  custodia-admin doctor [--server-config FILE] [--signer-config FILE] [--systemd] [--network]
  custodia-admin [global flags] client whoami
  custodia-admin [global flags] client list
  custodia-admin [global flags] client get --client-id ID
  custodia-admin [global flags] client create --client-id ID --mtls-subject SUBJECT
  custodia-admin [global flags] client issue --client-id ID --out-dir DIR [--signer-url URL]
  custodia-admin [global flags] client sign-csr --client-id ID --csr-file FILE --certificate-out FILE [--signer-url URL]
  custodia-admin [global flags] client revoke --client-id ID [--reason REASON]
  custodia-admin [global flags] certificate sign --client-id ID --csr-file FILE [--ttl-hours HOURS]
  custodia-admin certificate extract --input FILE --certificate-out FILE
  custodia-admin certificate bundle --certificate FILE --private-key FILE --ca FILE --out FILE
  custodia-admin [global flags] audit list [--limit N] [--outcome STATUS] [--action ACTION]
  custodia-admin [global flags] audit export [--limit N] [--out-file FILE] [--sha256-out FILE] [--events-out FILE]
  custodia-admin [global flags] audit verify [--limit N]
  custodia-admin [global flags] secret versions --key KEY [--namespace NS]
  custodia-admin [global flags] access list --key KEY [--namespace NS]
  custodia-admin [global flags] access requests [--limit N] [--secret-id ID] [--status STATUS]
  custodia-admin [global flags] access grant-request --key KEY [--namespace NS] --client-id ID --permissions read[,write,share]
  custodia-admin [global flags] access activate --key KEY [--namespace NS] --client-id ID --envelope-file FILE
  custodia-admin [global flags] access revoke --key KEY [--namespace NS] --client-id ID
  custodia-admin [global flags] lite upgrade-check --lite-env-file FILE --full-env-file FILE
  custodia-admin migration plan --source-config FILE --target-config FILE
  custodia-admin ca bootstrap-local [--out-dir DIR] [--admin-client-id ID] [--server-name NAME] [--generate-ca-passphrase]
  custodia-admin web totp generate [--issuer NAME] [--account NAME] [--format text|yaml|json]
  custodia-admin web totp configure [--config FILE] [--issuer NAME] [--account NAME]

global flags:
  --server-url URL
  --cert FILE
  --key FILE
  --ca FILE`)
}
