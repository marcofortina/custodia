// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"custodia/internal/build"
	"custodia/internal/certutil"
	"custodia/internal/model"

	sdk "custodia/pkg/client"
)

const (
	keyFileMode        os.FileMode = 0o600
	publicFileMode     os.FileMode = 0o644
	defaultPermissions             = sdk.PermissionAll
	defaultSharePerms              = sdk.PermissionRead
)

type app struct {
	stdout io.Writer
	stderr io.Writer
}

type transportFlags struct {
	configFile      string
	serverURL       string
	certFile        string
	keyFile         string
	caFile          string
	profileClientID string
}

type cryptoFlags struct {
	clientID   string
	cryptoKey  string
	recipients recipientFlags
}

type recipientFlags []string

func (f *recipientFlags) String() string { return strings.Join(*f, ",") }
func (f *recipientFlags) Set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return errors.New("recipient must not be empty")
	}
	*f = append(*f, value)
	return nil
}

type privateKeyFile struct {
	ClientID      string `json:"client_id"`
	Scheme        string `json:"scheme"`
	PrivateKeyB64 string `json:"private_key_b64"`
}

type publicKeyFile struct {
	ClientID     string `json:"client_id"`
	Scheme       string `json:"scheme"`
	PublicKeyB64 string `json:"public_key_b64"`
	Fingerprint  string `json:"fingerprint,omitempty"`
}

type clientConfigFile struct {
	ServerURL string `json:"server_url"`
	CertFile  string `json:"cert_file"`
	KeyFile   string `json:"key_file"`
	CAFile    string `json:"ca_file"`
	ClientID  string `json:"client_id,omitempty"`
	CryptoKey string `json:"crypto_key,omitempty"`
}

func main() {
	os.Exit((&app{stdout: os.Stdout, stderr: os.Stderr}).run(os.Args[1:]))
}

func (a *app) run(args []string) int {
	if len(args) == 0 {
		a.usage()
		return 2
	}
	switch args[0] {
	case "help", "--help", "-h":
		a.usage()
		return 0
	case "key":
		return a.runKey(args[1:])
	case "config":
		return a.runConfig(args[1:])
	case "doctor":
		return a.runDoctor(args[1:])
	case "mtls":
		return a.runMTLS(args[1:])
	case "secret":
		return a.runSecret(args[1:])
	case "version":
		info := build.Current()
		fmt.Fprintf(a.stdout, "%s %s %s\n", info.Version, info.Commit, info.Date)
		return 0
	default:
		fmt.Fprintf(a.stderr, "unknown command: %s\n", args[0])
		a.usage()
		return 2
	}
}

func (a *app) usage() {
	fmt.Fprintln(a.stdout, `Usage:
  custodia-client mtls enroll --client-id ID --server-url URL --enrollment-token TOKEN [--insecure]
  custodia-client mtls generate-csr --client-id ID [--private-key-out FILE --csr-out FILE]
  custodia-client mtls install-cert --client-id ID --cert-file FILE --ca-file FILE
  custodia-client key generate --client-id ID [--private-key-out FILE --public-key-out FILE]
  custodia-client key public --client-id ID --private-key FILE --public-key-out FILE
  custodia-client key publish --client-id ID|--config FILE [--crypto-key FILE]
  custodia-client key inspect --key FILE
  custodia-client config write --client-id ID [--server-url URL --out FILE --cert FILE --key FILE --ca FILE --crypto-key FILE]
  custodia-client config check --client-id ID|--config FILE
  custodia-client doctor --client-id ID|--config FILE [--online]
  custodia-client secret put --client-id ID --key KEY [--namespace NS] --value-file FILE [--recipient ID|ID=PUBLIC.json] [--permissions read[,write,share]|all|BITS]
  custodia-client secret get --client-id ID --key KEY [--namespace NS] [--out FILE]
  custodia-client secret update --client-id ID --key KEY [--namespace NS] --value-file FILE [--recipient ID|ID=PUBLIC.json] [--permissions read[,write,share]|all|BITS]
  custodia-client secret share --client-id ID --key KEY [--namespace NS] --target-client-id ID [--recipient ID=PUBLIC.json] [--permissions read[,write,share]|all|BITS]
  custodia-client secret versions --client-id ID --key KEY [--namespace NS] [--limit N]
  custodia-client secret access list --client-id ID --key KEY [--namespace NS] [--limit N]
  custodia-client secret access revoke --client-id ID --key KEY [--namespace NS] --target-client-id ID --yes
  custodia-client secret delete --client-id ID --key KEY [--namespace NS] [--cascade] --yes
  custodia-client secret list --client-id ID [--limit N]

Passing --client-id ID uses the standard profile at $XDG_CONFIG_HOME/custodia/ID or $HOME/.config/custodia/ID.
Common options may still be stored in a JSON config file and loaded with --config FILE or CUSTODIA_CLIENT_CONFIG.
For secret subcommands, --key identifies the secret; use --mtls-key for an explicit mTLS private key path.

Secret payloads are encrypted/decrypted locally. Custodia receives only ciphertext, crypto_metadata and opaque recipient envelopes.`)
}

func (a *app) runMTLS(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(a.stderr, "missing mtls subcommand")
		return 2
	}
	switch args[0] {
	case "enroll":
		return a.runMTLSEnroll(args[1:])
	case "generate-csr":
		return a.runMTLSGenerateCSR(args[1:])
	case "install-cert":
		return a.runMTLSInstallCert(args[1:])
	default:
		fmt.Fprintf(a.stderr, "unknown mtls subcommand: %s\n", args[0])
		return 2
	}
}

func (a *app) runMTLSEnroll(args []string) int {
	fs := newFlagSet("custodia-client mtls enroll", a.stderr)
	clientID := fs.String("client-id", "", "client id for the local profile")
	serverURL := fs.String("server-url", "", "Custodia API URL returned by the enrollment admin command")
	token := fs.String("enrollment-token", "", "one-shot enrollment token")
	insecure := fs.Bool("insecure", false, "skip TLS certificate verification during enrollment (unsafe; first-run or lab only)")
	if !parseFlags(fs, args, a.stderr) {
		return 2
	}
	id := strings.TrimSpace(*clientID)
	if id == "" || strings.TrimSpace(*serverURL) == "" || strings.TrimSpace(*token) == "" {
		fmt.Fprintln(a.stderr, "--client-id, --server-url and --enrollment-token are required")
		return 2
	}
	paths, err := defaultClientProfilePaths(id)
	if err != nil {
		fmt.Fprintf(a.stderr, "%v\n", err)
		return 2
	}
	if err := ensureEnrollmentTargetsAvailable(paths); err != nil {
		fmt.Fprintf(a.stderr, "%v\n", err)
		return 1
	}
	generated, err := certutil.GenerateClientCSR(id)
	if err != nil {
		fmt.Fprintf(a.stderr, "%v\n", err)
		return 1
	}
	claim := model.ClientEnrollmentClaimRequest{ClientID: id, EnrollmentToken: strings.TrimSpace(*token), CSRPem: string(generated.CSRPem)}
	response, err := claimEnrollment(strings.TrimSpace(*serverURL), *insecure, claim)
	if err != nil {
		fmt.Fprintf(a.stderr, "%v\n", err)
		return 1
	}
	if err := ensureClientProfileDir(paths.Dir); err != nil {
		fmt.Fprintf(a.stderr, "%v\n", err)
		return 1
	}
	if err := writeEnrollmentArtifacts(paths, generated, response); err != nil {
		fmt.Fprintf(a.stderr, "%v\n", err)
		return 1
	}
	fmt.Fprintf(a.stdout, "wrote mTLS private key to %s\n", paths.MTLSKey)
	fmt.Fprintf(a.stdout, "wrote client CSR to %s\n", paths.MTLSCSR)
	fmt.Fprintf(a.stdout, "installed client certificate to %s\n", paths.MTLSCert)
	fmt.Fprintf(a.stdout, "installed CA certificate to %s\n", paths.CA)
	fmt.Fprintf(a.stdout, "saved server URL to %s\n", paths.ServerURL)
	return 0
}

func ensureEnrollmentTargetsAvailable(paths clientProfilePaths) error {
	for _, path := range []string{paths.MTLSKey, paths.MTLSCSR, paths.MTLSCert, paths.CA, paths.ServerURL} {
		if strings.TrimSpace(path) == "" {
			return fmt.Errorf("enrollment output path is required")
		}
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("refusing to overwrite existing enrollment file: %s", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("check enrollment file %s: %w", path, err)
		}
	}
	return nil
}

func writeEnrollmentArtifacts(paths clientProfilePaths, generated *certutil.ClientCSR, response model.ClientEnrollmentClaimResponse) error {
	created := make([]string, 0, 5)
	write := func(path string, body []byte, mode os.FileMode) error {
		if err := writeExclusive(path, body, mode); err != nil {
			return err
		}
		created = append(created, path)
		return nil
	}
	cleanup := func() {
		for i := len(created) - 1; i >= 0; i-- {
			_ = os.Remove(created[i])
		}
	}
	if err := write(paths.MTLSKey, generated.PrivateKeyPEM, keyFileMode); err != nil {
		cleanup()
		return err
	}
	if err := write(paths.MTLSCSR, generated.CSRPem, publicFileMode); err != nil {
		cleanup()
		return err
	}
	if err := write(paths.MTLSCert, []byte(response.CertificatePEM), publicFileMode); err != nil {
		cleanup()
		return err
	}
	if err := write(paths.CA, []byte(response.CAPEM), publicFileMode); err != nil {
		cleanup()
		return err
	}
	if err := write(paths.ServerURL, []byte(strings.TrimSpace(response.ServerURL)+"\n"), publicFileMode); err != nil {
		cleanup()
		return err
	}
	return nil
}

func claimEnrollment(serverURL string, insecure bool, claim model.ClientEnrollmentClaimRequest) (model.ClientEnrollmentClaimResponse, error) {
	payload, err := json.Marshal(claim)
	if err != nil {
		return model.ClientEnrollmentClaimResponse{}, err
	}
	request, err := http.NewRequest(http.MethodPost, strings.TrimRight(serverURL, "/")+"/v1/client-enrollments/claim", strings.NewReader(string(payload)))
	if err != nil {
		return model.ClientEnrollmentClaimResponse{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 30 * time.Second}
	if insecure {
		client.Transport = insecureEnrollmentTransport()
	}
	response, err := client.Do(request)
	if err != nil {
		return model.ClientEnrollmentClaimResponse{}, enrollmentRequestError(serverURL, insecure, err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return model.ClientEnrollmentClaimResponse{}, err
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return model.ClientEnrollmentClaimResponse{}, enrollmentStatusError(response.StatusCode, response.Status, body)
	}
	var decoded model.ClientEnrollmentClaimResponse
	if err := json.Unmarshal(body, &decoded); err != nil {
		return model.ClientEnrollmentClaimResponse{}, err
	}
	return decoded, nil
}

func enrollmentRequestError(serverURL string, insecure bool, err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) && urlErr.Err != nil {
		err = urlErr.Err
	}

	hint := "check --server-url points to the reachable Custodia API endpoint and that the network path is open"
	var dnsErr *net.DNSError
	var unknownAuthority x509.UnknownAuthorityError
	var hostnameErr x509.HostnameError
	var certInvalidErr x509.CertificateInvalidError
	var netErr net.Error
	switch {
	case errors.As(err, &dnsErr):
		hint = "check the --server-url host name; DNS resolution failed. Use the reachable Custodia server name or IP from the enrollment runbook"
	case errors.As(err, &hostnameErr):
		hint = "the server certificate does not match --server-url. Use a DNS name or IP present in the server certificate SANs, or rebootstrap the server certificate"
	case errors.As(err, &unknownAuthority):
		if insecure {
			hint = "server certificate verification failed even though --insecure was requested; check the server TLS listener and certificate chain"
		} else {
			hint = "server certificate is not trusted. Install/trust the Custodia CA, use a --server-url covered by the certificate SANs, or use --insecure only for disposable lab bootstrap"
		}
	case errors.As(err, &certInvalidErr):
		hint = "server certificate is invalid or expired. Check the Custodia server certificate and CA material"
	case errors.As(err, &netErr) && netErr.Timeout():
		hint = "connection timed out. Check that the Custodia API listener is reachable from this client and that firewalls allow the port"
	}
	return fmt.Errorf("enrollment request failed: %w\nhint: %s", err, hint)
}

func enrollmentStatusError(statusCode int, status string, body []byte) error {
	code := enrollmentErrorCode(body)
	hint := "check the Custodia server logs and retry with a fresh enrollment command if needed"
	switch statusCode {
	case http.StatusBadRequest:
		hint = "check --client-id and the generated enrollment request; the server rejected the claim payload"
	case http.StatusUnauthorized, http.StatusForbidden:
		hint = "check that the enrollment token is valid, unexpired and unused, and copy the token exactly from the admin enrollment command"
	case http.StatusNotFound:
		hint = "check --server-url; it must point to the Custodia API listener, not the Web Console or signer listener"
	case http.StatusTooManyRequests:
		hint = "the server is rate limiting enrollment claims; wait and retry with a valid token"
	}
	if statusCode >= 500 {
		hint = "check the Custodia server and signer logs; enrollment signing may be unavailable"
	}
	return fmt.Errorf("enrollment failed: %s: %s\nhint: %s", status, code, hint)
}

func enrollmentErrorCode(body []byte) string {
	var payload struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &payload); err == nil && strings.TrimSpace(payload.Error) != "" {
		return strings.TrimSpace(payload.Error)
	}
	if strings.TrimSpace(string(body)) == "" {
		return "empty_error_response"
	}
	return "non_json_error_response"
}

func insecureEnrollmentTransport() *http.Transport {
	// codeql[go/disabled-certificate-check]: Enrollment uses normal TLS verification by default;
	// this transport is only selected when the user explicitly passes --insecure for
	// first-run or lab bootstrap scenarios.
	return &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}}
}

func (a *app) runMTLSGenerateCSR(args []string) int {
	fs := newFlagSet("custodia-client mtls generate-csr", a.stderr)
	clientID := fs.String("client-id", "", "client id for the CSR subject")
	privateKeyOut := fs.String("private-key-out", "", "path for generated mTLS private key PEM")
	csrOut := fs.String("csr-out", "", "path for generated CSR PEM")
	if !parseFlags(fs, args, a.stderr) {
		return 2
	}
	id := strings.TrimSpace(*clientID)
	if id == "" {
		fmt.Fprintln(a.stderr, "--client-id is required")
		return 2
	}
	paths, err := defaultClientProfilePaths(id)
	if err != nil {
		fmt.Fprintf(a.stderr, "%v\n", err)
		return 2
	}
	if strings.TrimSpace(*privateKeyOut) == "" {
		*privateKeyOut = paths.MTLSKey
	}
	if strings.TrimSpace(*csrOut) == "" {
		*csrOut = paths.MTLSCSR
	}
	if err := ensureClientProfileDir(paths.Dir); err != nil {
		fmt.Fprintf(a.stderr, "%v\n", err)
		return 1
	}
	generated, err := certutil.GenerateClientCSR(id)
	if err != nil {
		fmt.Fprintf(a.stderr, "%v\n", err)
		return 1
	}
	if err := writeExclusive(*privateKeyOut, generated.PrivateKeyPEM, keyFileMode); err != nil {
		fmt.Fprintf(a.stderr, "%v\n", err)
		return 1
	}
	if err := writeExclusive(*csrOut, generated.CSRPem, publicFileMode); err != nil {
		fmt.Fprintf(a.stderr, "%v\n", err)
		return 1
	}
	fmt.Fprintf(a.stdout, "wrote mTLS private key to %s\n", *privateKeyOut)
	fmt.Fprintf(a.stdout, "wrote client CSR to %s\n", *csrOut)
	return 0
}

func (a *app) runMTLSInstallCert(args []string) int {
	fs := newFlagSet("custodia-client mtls install-cert", a.stderr)
	clientID := fs.String("client-id", "", "client id for the local profile")
	certFile := fs.String("cert-file", "", "signed mTLS client certificate PEM")
	caFile := fs.String("ca-file", "", "Custodia CA certificate PEM")
	certOut := fs.String("cert-out", "", "destination for the installed client certificate")
	caOut := fs.String("ca-out", "", "destination for the installed CA certificate")
	if !parseFlags(fs, args, a.stderr) {
		return 2
	}
	id := strings.TrimSpace(*clientID)
	if id == "" || strings.TrimSpace(*certFile) == "" || strings.TrimSpace(*caFile) == "" {
		fmt.Fprintln(a.stderr, "--client-id, --cert-file and --ca-file are required")
		return 2
	}
	paths, err := defaultClientProfilePaths(id)
	if err != nil {
		fmt.Fprintf(a.stderr, "%v\n", err)
		return 2
	}
	if strings.TrimSpace(*certOut) == "" {
		*certOut = paths.MTLSCert
	}
	if strings.TrimSpace(*caOut) == "" {
		*caOut = paths.CA
	}
	if err := ensureClientProfileDir(paths.Dir); err != nil {
		fmt.Fprintf(a.stderr, "%v\n", err)
		return 1
	}
	if err := copyFileExclusive(*certFile, *certOut, publicFileMode); err != nil {
		fmt.Fprintf(a.stderr, "%v\n", err)
		return 1
	}
	if err := copyFileExclusive(*caFile, *caOut, publicFileMode); err != nil {
		fmt.Fprintf(a.stderr, "%v\n", err)
		return 1
	}
	fmt.Fprintf(a.stdout, "installed client certificate to %s\n", *certOut)
	fmt.Fprintf(a.stdout, "installed CA certificate to %s\n", *caOut)
	return 0
}

func (a *app) runConfig(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(a.stderr, "missing config subcommand")
		return 2
	}
	switch args[0] {
	case "write":
		return a.runConfigWrite(args[1:])
	case "check":
		return a.runConfigCheck(args[1:])
	default:
		fmt.Fprintf(a.stderr, "unknown config subcommand: %s\n", args[0])
		return 2
	}
}

func (a *app) runConfigWrite(args []string) int {
	fs := newFlagSet("custodia-client config write", a.stderr)
	out := fs.String("out", "", "client config output JSON")
	serverURL := fs.String("server-url", "", "Custodia API base URL")
	certFile := fs.String("cert", "", "mTLS client certificate")
	keyFile := fs.String("key", "", "mTLS client private key")
	caFile := fs.String("ca", "", "Custodia CA certificate")
	clientID := fs.String("client-id", "", "local client id")
	cryptoKey := fs.String("crypto-key", "", "local X25519 private key JSON")
	if !parseFlags(fs, args, a.stderr) {
		return 2
	}
	id := strings.TrimSpace(*clientID)
	if id != "" {
		paths, err := defaultClientProfilePaths(id)
		if err != nil {
			fmt.Fprintf(a.stderr, "%v\n", err)
			return 2
		}
		if strings.TrimSpace(*out) == "" {
			*out = paths.Config
		}
		if strings.TrimSpace(*serverURL) == "" {
			profileURL, err := readDefaultServerURL(id)
			if err != nil {
				fmt.Fprintf(a.stderr, "%v\n", err)
				return 2
			}
			*serverURL = profileURL
		}
		if strings.TrimSpace(*certFile) == "" {
			*certFile = paths.MTLSCert
		}
		if strings.TrimSpace(*keyFile) == "" {
			*keyFile = paths.MTLSKey
		}
		if strings.TrimSpace(*caFile) == "" {
			*caFile = paths.CA
		}
		if strings.TrimSpace(*cryptoKey) == "" {
			*cryptoKey = paths.CryptoPrivate
		}
		if err := ensureClientProfileDir(paths.Dir); err != nil {
			fmt.Fprintf(a.stderr, "%v\n", err)
			return 1
		}
	}
	if strings.TrimSpace(*out) == "" || strings.TrimSpace(*serverURL) == "" || strings.TrimSpace(*certFile) == "" || strings.TrimSpace(*keyFile) == "" || strings.TrimSpace(*caFile) == "" {
		fmt.Fprintln(a.stderr, "--client-id with an enrolled profile, or explicit --server-url, --out, --cert, --key and --ca are required")
		return 2
	}
	config := clientConfigFile{ServerURL: strings.TrimSpace(*serverURL), CertFile: strings.TrimSpace(*certFile), KeyFile: strings.TrimSpace(*keyFile), CAFile: strings.TrimSpace(*caFile), ClientID: id, CryptoKey: strings.TrimSpace(*cryptoKey)}
	if err := writeJSONFileExclusive(*out, config, keyFileMode); err != nil {
		fmt.Fprintf(a.stderr, "%v\n", err)
		return 1
	}
	fmt.Fprintf(a.stdout, "wrote %s\n", *out)
	return 0
}
func (a *app) runConfigCheck(args []string) int {
	fs := newFlagSet("custodia-client config check", a.stderr)
	configFile := fs.String("config", envDefault("CUSTODIA_CLIENT_CONFIG", ""), "Custodia client config JSON")
	clientID := fs.String("client-id", envDefault("CUSTODIA_CLIENT_ID", ""), "local client id for the standard profile")
	if !parseFlags(fs, args, a.stderr) {
		return 2
	}
	if strings.TrimSpace(*configFile) == "" && strings.TrimSpace(*clientID) != "" {
		path, err := defaultClientConfigPath(*clientID)
		if err != nil {
			fmt.Fprintf(a.stderr, "%v\n", err)
			return 2
		}
		*configFile = path
	}
	if strings.TrimSpace(*configFile) == "" {
		fmt.Fprintln(a.stderr, "--client-id or --config is required")
		return 2
	}
	config, err := validateClientConfigFile(*configFile)
	if err != nil {
		fmt.Fprintf(a.stderr, "%v\n", err)
		return 1
	}
	return writeJSON(a.stdout, map[string]any{
		"status":         "ok",
		"server_url":     config.ServerURL,
		"client_id":      config.ClientID,
		"has_crypto_key": strings.TrimSpace(config.CryptoKey) != "",
	})
}
func (a *app) runKey(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(a.stderr, "missing key subcommand")
		return 2
	}
	switch args[0] {
	case "generate":
		return a.runKeyGenerate(args[1:])
	case "public":
		return a.runKeyPublic(args[1:])
	case "publish":
		return a.runKeyPublish(args[1:])
	case "inspect":
		return a.runKeyInspect(args[1:])
	default:
		fmt.Fprintf(a.stderr, "unknown key subcommand: %s\n", args[0])
		return 2
	}
}

func (a *app) runKeyGenerate(args []string) int {
	fs := newFlagSet("custodia-client key generate", a.stderr)
	clientID := fs.String("client-id", "", "local Custodia client id")
	privateOut := fs.String("private-key-out", "", "private X25519 key output JSON")
	publicOut := fs.String("public-key-out", "", "public X25519 key output JSON")
	if !parseFlags(fs, args, a.stderr) {
		return 2
	}
	id := strings.TrimSpace(*clientID)
	if id == "" {
		fmt.Fprintln(a.stderr, "--client-id is required")
		return 2
	}
	paths, err := defaultClientProfilePaths(id)
	if err != nil {
		fmt.Fprintf(a.stderr, "%v\n", err)
		return 2
	}
	if strings.TrimSpace(*privateOut) == "" {
		*privateOut = paths.CryptoPrivate
	}
	if strings.TrimSpace(*publicOut) == "" {
		*publicOut = paths.CryptoPublic
	}
	if err := ensureClientProfileDir(paths.Dir); err != nil {
		fmt.Fprintf(a.stderr, "%v\n", err)
		return 1
	}
	privateKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, privateKey); err != nil {
		fmt.Fprintf(a.stderr, "generate private key: %v\n", err)
		return 1
	}
	if err := writeKeyPair(id, privateKey, *privateOut, *publicOut); err != nil {
		fmt.Fprintf(a.stderr, "%v\n", err)
		return 1
	}
	fmt.Fprintf(a.stdout, "wrote application private key to %s\n", *privateOut)
	fmt.Fprintf(a.stdout, "wrote application public key to %s\n", *publicOut)
	return 0
}
func (a *app) runKeyPublic(args []string) int {
	fs := newFlagSet("custodia-client key public", a.stderr)
	clientID := fs.String("client-id", "", "local Custodia client id override")
	privateIn := fs.String("private-key", "", "private X25519 key JSON")
	publicOut := fs.String("public-key-out", "", "public X25519 key output JSON")
	if !parseFlags(fs, args, a.stderr) {
		return 2
	}
	if strings.TrimSpace(*privateIn) == "" || strings.TrimSpace(*publicOut) == "" {
		fmt.Fprintln(a.stderr, "--private-key and --public-key-out are required")
		return 2
	}
	keyFile, privateKey, err := readPrivateKeyFile(*privateIn)
	if err != nil {
		fmt.Fprintf(a.stderr, "%v\n", err)
		return 1
	}
	id := strings.TrimSpace(*clientID)
	if id == "" {
		id = keyFile.ClientID
	}
	if id == "" {
		fmt.Fprintln(a.stderr, "client id is required in --client-id or private key file")
		return 2
	}
	if err := writePublicKey(id, privateKey, *publicOut); err != nil {
		fmt.Fprintf(a.stderr, "%v\n", err)
		return 1
	}
	fmt.Fprintf(a.stdout, "wrote %s\n", *publicOut)
	return 0
}

func (a *app) runKeyPublish(args []string) int {
	fs := newFlagSet("custodia-client key publish", a.stderr)
	var transport transportFlags
	registerTransportFlags(fs, &transport)
	var crypto cryptoFlags
	registerCryptoFlagsNoRecipients(fs, &crypto)
	if !parseFlags(fs, args, a.stderr) {
		return 2
	}
	if err := defaultTransportConfigFromClientID(&transport, crypto.clientID); err != nil {
		fmt.Fprintf(a.stderr, "%v\n", err)
		return 2
	}
	if err := applyClientConfig(&transport, &crypto); err != nil {
		fmt.Fprintf(a.stderr, "%v\n", err)
		return 1
	}
	payload, err := publishPublicKeyPayload(crypto)
	if err != nil {
		fmt.Fprintf(a.stderr, "%v\n", err)
		return 1
	}
	client, err := buildTransportClient(transport)
	if err != nil {
		fmt.Fprintf(a.stderr, "%v\n", err)
		return 1
	}
	published, err := client.PublishClientPublicKeyPayload(payload)
	if err != nil {
		fmt.Fprintf(a.stderr, "publish public key: %v\n", err)
		return 1
	}
	return writeJSON(a.stdout, map[string]any{"client_id": published.ClientID, "scheme": published.Scheme, "fingerprint": published.Fingerprint, "status": "published"})
}

func (a *app) runKeyInspect(args []string) int {
	fs := newFlagSet("custodia-client key inspect", a.stderr)
	keyPath := fs.String("key", "", "private X25519 key JSON")
	if !parseFlags(fs, args, a.stderr) {
		return 2
	}
	if strings.TrimSpace(*keyPath) == "" {
		fmt.Fprintln(a.stderr, "--key is required")
		return 2
	}
	payload, privateKey, err := readPrivateKeyFile(*keyPath)
	if err != nil {
		fmt.Fprintf(a.stderr, "%v\n", err)
		return 1
	}
	publicKey, err := sdk.DeriveX25519RecipientPublicKey(firstNonEmpty(payload.ClientID, "validation"), privateKey)
	if err != nil {
		fmt.Fprintf(a.stderr, "derive public key: %v\n", err)
		return 1
	}
	return writeJSON(a.stdout, map[string]any{
		"client_id":              payload.ClientID,
		"scheme":                 payload.Scheme,
		"public_key_fingerprint": fingerprint(publicKey.PublicKey),
	})
}

func (a *app) runSecret(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(a.stderr, "missing secret subcommand")
		return 2
	}
	switch args[0] {
	case "put":
		return a.runSecretPut(args[1:])
	case "get":
		return a.runSecretGet(args[1:])
	case "share":
		return a.runSecretShare(args[1:])
	case "delete":
		return a.runSecretDelete(args[1:])
	case "update":
		return a.runSecretVersionPut(args[1:])
	case "revoke":
		return a.runSecretAccessRevoke(args[1:])
	case "version":
		return a.runSecretVersion(args[1:])
	case "versions":
		return a.runSecretVersionsList(args[1:])
	case "access":
		return a.runSecretAccess(args[1:])
	case "list":
		return a.runSecretList(args[1:])
	default:
		fmt.Fprintf(a.stderr, "unknown secret subcommand: %s\n", args[0])
		return 2
	}
}

func (a *app) runSecretPut(args []string) int {
	fs := newFlagSet("custodia-client secret put", a.stderr)
	var transport transportFlags
	registerSecretTransportFlags(fs, &transport)
	var crypto cryptoFlags
	registerCryptoFlags(fs, &crypto)
	namespace := fs.String("namespace", "default", "secret namespace")
	key := fs.String("key", "", "secret key")
	valueFile := fs.String("value-file", "", "plaintext file to encrypt locally")
	permissions := fs.String("permissions", "all", "permission bits or names: read, write, share, all")
	if !parseFlags(fs, args, a.stderr) {
		return 2
	}
	secretKey := strings.TrimSpace(*key)
	if secretKey == "" || strings.TrimSpace(*valueFile) == "" {
		fmt.Fprintln(a.stderr, "--key and --value-file are required")
		return 2
	}
	permissionBits, err := parsePermissionBits(*permissions, defaultPermissions)
	if err != nil {
		fmt.Fprintf(a.stderr, "%v\n", err)
		return 2
	}
	plaintext, err := os.ReadFile(*valueFile)
	if err != nil {
		fmt.Fprintf(a.stderr, "read plaintext: %v\n", err)
		return 1
	}
	cryptoClient, recipients, err := buildCryptoClient(transport, crypto)
	if err != nil {
		fmt.Fprintf(a.stderr, "%v\n", err)
		return 1
	}
	ref, err := cryptoClient.CreateEncryptedSecret(context.Background(), sdk.CreateEncryptedSecretRequest{
		Namespace:   *namespace,
		Key:         secretKey,
		Plaintext:   plaintext,
		Recipients:  recipients,
		Permissions: permissionBits,
	})
	if err != nil {
		fmt.Fprintf(a.stderr, "create encrypted secret: %v\n", err)
		return 1
	}
	return writeJSON(a.stdout, ref)
}

func (a *app) runSecretGet(args []string) int {
	fs := newFlagSet("custodia-client secret get", a.stderr)
	var transport transportFlags
	registerSecretTransportFlags(fs, &transport)
	var crypto cryptoFlags
	registerCryptoFlagsNoRecipients(fs, &crypto)
	namespace := fs.String("namespace", "default", "secret namespace")
	key := fs.String("key", "", "secret key")
	out := fs.String("out", "-", "plaintext output file or - for stdout")
	if !parseFlags(fs, args, a.stderr) {
		return 2
	}
	if strings.TrimSpace(*key) == "" {
		fmt.Fprintln(a.stderr, "--key is required")
		return 2
	}
	cryptoClient, _, err := buildCryptoClient(transport, crypto)
	if err != nil {
		fmt.Fprintf(a.stderr, "%v\n", err)
		return 1
	}
	secret, err := cryptoClient.ReadDecryptedSecretByKey(context.Background(), *namespace, *key)
	if err != nil {
		fmt.Fprintf(a.stderr, "read encrypted secret: %v\n", err)
		return 1
	}
	if err := writeOutput(a.stdout, *out, secret.Plaintext, keyFileMode); err != nil {
		fmt.Fprintf(a.stderr, "%v\n", err)
		return 1
	}
	if *out != "-" {
		fmt.Fprintf(a.stdout, "wrote %s\n", *out)
	}
	return 0
}

func (a *app) runSecretDelete(args []string) int {
	fs := newFlagSet("custodia-client secret delete", a.stderr)
	var transport transportFlags
	registerSecretTransportFlags(fs, &transport)
	clientID := fs.String("client-id", envDefault("CUSTODIA_CLIENT_ID", ""), "local client id for the standard profile")
	namespace := fs.String("namespace", "default", "secret namespace")
	key := fs.String("key", "", "secret key")
	cascade := fs.Bool("cascade", false, "delete shared owner secret after revoking active shares")
	confirmed := fs.Bool("yes", false, "confirm secret deletion or shared-key removal")
	if !parseFlags(fs, args, a.stderr) {
		return 2
	}
	transport.profileClientID = strings.TrimSpace(*clientID)
	if strings.TrimSpace(*key) == "" {
		fmt.Fprintln(a.stderr, "--key is required")
		return 2
	}
	if !*confirmed {
		fmt.Fprintln(a.stderr, "--yes is required to delete a secret")
		return 2
	}
	client, err := buildTransportClient(transport)
	if err != nil {
		fmt.Fprintf(a.stderr, "%v\n", err)
		return 1
	}
	if err := client.DeleteSecretByKey(*namespace, *key, *cascade); err != nil {
		fmt.Fprintf(a.stderr, "delete secret: %v\n", err)
		return 1
	}
	return writeJSON(a.stdout, map[string]string{"namespace": strings.TrimSpace(*namespace), "key": strings.TrimSpace(*key), "status": "deleted"})
}

func (a *app) runSecretShare(args []string) int {
	fs := newFlagSet("custodia-client secret share", a.stderr)
	var transport transportFlags
	registerSecretTransportFlags(fs, &transport)
	var crypto cryptoFlags
	registerCryptoFlags(fs, &crypto)
	namespace := fs.String("namespace", "default", "secret namespace")
	key := fs.String("key", "", "secret key")
	targetClientID := fs.String("target-client-id", "", "target recipient client id")
	permissions := fs.String("permissions", "read", "permission bits or names: read, write, share, all")
	if !parseFlags(fs, args, a.stderr) {
		return 2
	}
	if strings.TrimSpace(*key) == "" || strings.TrimSpace(*targetClientID) == "" {
		fmt.Fprintln(a.stderr, "--key and --target-client-id are required")
		return 2
	}
	permissionBits, err := parsePermissionBits(*permissions, defaultSharePerms)
	if err != nil {
		fmt.Fprintf(a.stderr, "%v\n", err)
		return 2
	}
	cryptoClient, _, err := buildCryptoClient(transport, crypto)
	if err != nil {
		fmt.Fprintf(a.stderr, "%v\n", err)
		return 1
	}
	if err := cryptoClient.ShareEncryptedSecretByKey(context.Background(), *namespace, *key, sdk.ShareEncryptedSecretRequest{TargetClientID: *targetClientID, Permissions: permissionBits}); err != nil {
		fmt.Fprintf(a.stderr, "share encrypted secret: %v\n", err)
		return 1
	}
	return writeJSON(a.stdout, map[string]string{"namespace": strings.TrimSpace(*namespace), "key": strings.TrimSpace(*key), "target_client_id": *targetClientID, "status": "shared"})
}

func (a *app) runSecretVersion(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(a.stderr, "missing secret version subcommand")
		return 2
	}
	if args[0] != "put" {
		fmt.Fprintf(a.stderr, "unknown secret version subcommand: %s\n", args[0])
		return 2
	}
	return a.runSecretVersionPut(args[1:])
}

func (a *app) runSecretVersionPut(args []string) int {
	fs := newFlagSet("custodia-client secret update", a.stderr)
	var transport transportFlags
	registerSecretTransportFlags(fs, &transport)
	var crypto cryptoFlags
	registerCryptoFlags(fs, &crypto)
	namespace := fs.String("namespace", "default", "secret namespace")
	key := fs.String("key", "", "secret key")
	valueFile := fs.String("value-file", "", "plaintext file to encrypt locally")
	permissions := fs.String("permissions", "all", "permission bits or names: read, write, share, all")
	if !parseFlags(fs, args, a.stderr) {
		return 2
	}
	if strings.TrimSpace(*key) == "" || strings.TrimSpace(*valueFile) == "" {
		fmt.Fprintln(a.stderr, "--key and --value-file are required")
		return 2
	}
	permissionBits, err := parsePermissionBits(*permissions, defaultPermissions)
	if err != nil {
		fmt.Fprintf(a.stderr, "%v\n", err)
		return 2
	}
	plaintext, err := os.ReadFile(*valueFile)
	if err != nil {
		fmt.Fprintf(a.stderr, "read plaintext: %v\n", err)
		return 1
	}
	cryptoClient, recipients, err := buildCryptoClient(transport, crypto)
	if err != nil {
		fmt.Fprintf(a.stderr, "%v\n", err)
		return 1
	}
	ref, err := cryptoClient.CreateEncryptedSecretVersionByKey(context.Background(), *namespace, *key, sdk.CreateEncryptedSecretVersionRequest{Plaintext: plaintext, Recipients: recipients, Permissions: permissionBits})
	if err != nil {
		fmt.Fprintf(a.stderr, "create encrypted secret version: %v\n", err)
		return 1
	}
	return writeJSON(a.stdout, ref)
}

func (a *app) runSecretVersionsList(args []string) int {
	fs := newFlagSet("custodia-client secret versions", a.stderr)
	var transport transportFlags
	registerSecretTransportFlags(fs, &transport)
	clientID := fs.String("client-id", envDefault("CUSTODIA_CLIENT_ID", ""), "local client id for the standard profile")
	namespace := fs.String("namespace", "default", "secret namespace")
	key := fs.String("key", "", "secret key")
	limit := fs.Int("limit", 100, "maximum rows to return")
	if !parseFlags(fs, args, a.stderr) {
		return 2
	}
	transport.profileClientID = strings.TrimSpace(*clientID)
	if strings.TrimSpace(*key) == "" {
		fmt.Fprintln(a.stderr, "--key is required")
		return 2
	}
	client, err := buildTransportClient(transport)
	if err != nil {
		fmt.Fprintf(a.stderr, "%v\n", err)
		return 1
	}
	versions, err := client.ListSecretVersionMetadataByKey(*namespace, *key, *limit)
	if err != nil {
		fmt.Fprintf(a.stderr, "list secret versions: %v\n", err)
		return 1
	}
	return writeJSON(a.stdout, map[string]any{"versions": versions})
}

func (a *app) runSecretAccess(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(a.stderr, "missing secret access subcommand")
		return 2
	}
	switch args[0] {
	case "list":
		return a.runSecretAccessList(args[1:])
	case "revoke":
		return a.runSecretAccessRevoke(args[1:])
	default:
		fmt.Fprintf(a.stderr, "unknown secret access subcommand: %s\n", args[0])
		return 2
	}
}

func (a *app) runSecretAccessList(args []string) int {
	fs := newFlagSet("custodia-client secret access list", a.stderr)
	var transport transportFlags
	registerSecretTransportFlags(fs, &transport)
	clientID := fs.String("client-id", envDefault("CUSTODIA_CLIENT_ID", ""), "local client id for the standard profile")
	namespace := fs.String("namespace", "default", "secret namespace")
	key := fs.String("key", "", "secret key")
	limit := fs.Int("limit", 100, "maximum rows to return")
	if !parseFlags(fs, args, a.stderr) {
		return 2
	}
	transport.profileClientID = strings.TrimSpace(*clientID)
	if strings.TrimSpace(*key) == "" {
		fmt.Fprintln(a.stderr, "--key is required")
		return 2
	}
	client, err := buildTransportClient(transport)
	if err != nil {
		fmt.Fprintf(a.stderr, "%v\n", err)
		return 1
	}
	access, err := client.ListSecretAccessMetadataByKey(*namespace, *key, *limit)
	if err != nil {
		fmt.Fprintf(a.stderr, "list secret access: %v\n", err)
		return 1
	}
	return writeJSON(a.stdout, map[string]any{"access": access})
}

func (a *app) runSecretAccessRevoke(args []string) int {
	fs := newFlagSet("custodia-client secret access revoke", a.stderr)
	var transport transportFlags
	registerSecretTransportFlags(fs, &transport)
	clientID := fs.String("client-id", envDefault("CUSTODIA_CLIENT_ID", ""), "local client id for the standard profile")
	namespace := fs.String("namespace", "default", "secret namespace")
	key := fs.String("key", "", "secret key")
	targetClientID := fs.String("target-client-id", "", "target client id whose future access is revoked")
	confirmed := fs.Bool("yes", false, "confirm access revocation")
	if !parseFlags(fs, args, a.stderr) {
		return 2
	}
	transport.profileClientID = strings.TrimSpace(*clientID)
	if strings.TrimSpace(*key) == "" || strings.TrimSpace(*targetClientID) == "" {
		fmt.Fprintln(a.stderr, "--key and --target-client-id are required")
		return 2
	}
	if !*confirmed {
		fmt.Fprintln(a.stderr, "--yes is required to revoke secret access")
		return 2
	}
	client, err := buildTransportClient(transport)
	if err != nil {
		fmt.Fprintf(a.stderr, "%v\n", err)
		return 1
	}
	if err := client.RevokeAccessByKey(*namespace, *key, *targetClientID); err != nil {
		fmt.Fprintf(a.stderr, "revoke secret access: %v\n", err)
		return 1
	}
	return writeJSON(a.stdout, map[string]string{"namespace": strings.TrimSpace(*namespace), "key": strings.TrimSpace(*key), "target_client_id": *targetClientID, "status": "revoked"})
}

func (a *app) runSecretList(args []string) int {
	fs := newFlagSet("custodia-client secret list", a.stderr)
	var transport transportFlags
	registerSecretTransportFlags(fs, &transport)
	clientID := fs.String("client-id", envDefault("CUSTODIA_CLIENT_ID", ""), "local client id for the standard profile")
	limit := fs.Int("limit", 100, "maximum rows to return")
	if !parseFlags(fs, args, a.stderr) {
		return 2
	}
	transport.profileClientID = strings.TrimSpace(*clientID)
	client, err := buildTransportClient(transport)
	if err != nil {
		fmt.Fprintf(a.stderr, "%v\n", err)
		return 1
	}
	secrets, err := client.ListSecretMetadata(*limit)
	if err != nil {
		fmt.Fprintf(a.stderr, "list secrets: %v\n", err)
		return 1
	}
	return writeJSON(a.stdout, map[string]any{"secrets": secrets})
}

func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

func parseFlags(fs *flag.FlagSet, args []string, stderr io.Writer) bool {
	if err := fs.Parse(args); err != nil {
		return false
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "unexpected argument: %s\n", fs.Arg(0))
		return false
	}
	return true
}

func parsePermissionBits(value string, fallback int) (int, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback, nil
	}
	if bits, err := strconv.Atoi(value); err == nil {
		if !model.ValidPermissionBits(bits) {
			return 0, fmt.Errorf("invalid --permissions value %q; use read, write, share, all, or a valid bitmask", value)
		}
		return bits, nil
	}

	bits := 0
	for _, token := range strings.Split(value, ",") {
		switch strings.ToLower(strings.TrimSpace(token)) {
		case "read":
			bits |= int(model.PermissionRead)
		case "write":
			bits |= int(model.PermissionWrite)
		case "share":
			bits |= int(model.PermissionShare)
		case "all":
			bits |= int(model.PermissionAll)
		case "":
			return 0, fmt.Errorf("invalid --permissions value %q; empty permission token", value)
		default:
			return 0, fmt.Errorf("invalid --permissions value %q; use read, write, share, all, or a valid bitmask", value)
		}
	}
	if !model.ValidPermissionBits(bits) {
		return 0, fmt.Errorf("invalid --permissions value %q; use read, write, share, all, or a valid bitmask", value)
	}
	return bits, nil
}

func registerTransportFlags(fs *flag.FlagSet, flags *transportFlags) {
	registerTransportFlagsWithKeyName(fs, flags, "key")
}

func registerSecretTransportFlags(fs *flag.FlagSet, flags *transportFlags) {
	registerTransportFlagsWithKeyName(fs, flags, "mtls-key")
}

func registerTransportFlagsWithKeyName(fs *flag.FlagSet, flags *transportFlags, keyFlagName string) {
	fs.StringVar(&flags.configFile, "config", envDefault("CUSTODIA_CLIENT_CONFIG", ""), "Custodia client config JSON")
	fs.StringVar(&flags.serverURL, "server-url", envDefault("CUSTODIA_BASE_URL", ""), "Custodia API base URL")
	fs.StringVar(&flags.certFile, "cert", envDefault("CUSTODIA_CLIENT_CERT", ""), "mTLS client certificate")
	fs.StringVar(&flags.keyFile, keyFlagName, envDefault("CUSTODIA_CLIENT_KEY", ""), "mTLS client private key")
	fs.StringVar(&flags.caFile, "ca", envDefault("CUSTODIA_CA_CERT", ""), "Custodia CA certificate")
}

func registerCryptoFlags(fs *flag.FlagSet, flags *cryptoFlags) {
	registerCryptoFlagsNoRecipients(fs, flags)
	fs.Var(&flags.recipients, "recipient", "recipient client id resolved from the server, or pinned public key override as ID=FILE or FILE")
}

func registerCryptoFlagsNoRecipients(fs *flag.FlagSet, flags *cryptoFlags) {
	fs.StringVar(&flags.clientID, "client-id", envDefault("CUSTODIA_CLIENT_ID", ""), "local client id")
	fs.StringVar(&flags.cryptoKey, "crypto-key", envDefault("CUSTODIA_CRYPTO_KEY", ""), "local X25519 private key JSON")
}

func buildTransportClient(transport transportFlags) (*sdk.Client, error) {
	if err := defaultTransportConfigFromClientID(&transport, transport.profileClientID); err != nil {
		return nil, err
	}
	if err := applyClientConfig(&transport, nil); err != nil {
		return nil, err
	}
	if strings.TrimSpace(transport.serverURL) == "" || strings.TrimSpace(transport.certFile) == "" || strings.TrimSpace(transport.keyFile) == "" || strings.TrimSpace(transport.caFile) == "" {
		return nil, fmt.Errorf("--server-url, --cert, --key and --ca are required")
	}
	client, err := sdk.New(sdk.Config{ServerURL: transport.serverURL, CertFile: transport.certFile, KeyFile: transport.keyFile, CAFile: transport.caFile})
	if err != nil {
		return nil, fmt.Errorf("create transport client: %w", err)
	}
	return client, nil
}

func buildCryptoClient(transport transportFlags, crypto cryptoFlags) (*sdk.CryptoClient, []string, error) {
	if err := defaultTransportConfigFromClientID(&transport, crypto.clientID); err != nil {
		return nil, nil, err
	}
	if err := applyClientConfig(&transport, &crypto); err != nil {
		return nil, nil, err
	}
	if strings.TrimSpace(crypto.cryptoKey) == "" && strings.TrimSpace(crypto.clientID) != "" {
		paths, err := defaultClientProfilePaths(crypto.clientID)
		if err != nil {
			return nil, nil, err
		}
		crypto.cryptoKey = paths.CryptoPrivate
	}
	if strings.TrimSpace(crypto.cryptoKey) == "" {
		return nil, nil, fmt.Errorf("--crypto-key is required; pass --client-id for a standard profile created by key generate/config write, pass --config, or pass --crypto-key explicitly")
	}
	keyFile, privateKey, err := readPrivateKeyFile(crypto.cryptoKey)
	if err != nil {
		return nil, nil, err
	}
	clientID := strings.TrimSpace(crypto.clientID)
	if clientID == "" {
		clientID = keyFile.ClientID
	}
	if clientID == "" {
		return nil, nil, fmt.Errorf("client id is required in --client-id or crypto key file")
	}
	handle, err := sdk.NewX25519PrivateKeyHandle(clientID, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("load private key: %w", err)
	}
	publicKeys := map[string]sdk.RecipientPublicKey{}
	selfPublic, err := sdk.DeriveX25519RecipientPublicKey(clientID, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("derive local public key: %w", err)
	}
	publicKeys[clientID] = selfPublic
	recipientIDs := make([]string, 0, len(crypto.recipients))
	for _, spec := range crypto.recipients {
		recipientID, publicKey, pinned, err := readRecipientSpec(spec)
		if err != nil {
			return nil, nil, err
		}
		if pinned {
			publicKeys[recipientID] = publicKey
		}
		recipientIDs = append(recipientIDs, recipientID)
	}
	transportClient, err := buildTransportClient(transport)
	if err != nil {
		return nil, nil, err
	}
	cryptoClient, err := transportClient.WithCrypto(sdk.CryptoOptions{PublicKeyResolver: serverBackedResolver{local: staticResolver(publicKeys), transport: transportClient}, PrivateKeyProvider: staticPrivateKeyProvider{handle: handle}, RandomSource: rand.Reader, Clock: sdk.SystemClock{}})
	if err != nil {
		return nil, nil, fmt.Errorf("create crypto client: %w", err)
	}
	return cryptoClient, recipientIDs, nil
}

func applyClientConfig(transport *transportFlags, crypto *cryptoFlags) error {
	if transport == nil || strings.TrimSpace(transport.configFile) == "" {
		return nil
	}
	config, err := readClientConfigFile(transport.configFile)
	if err != nil {
		return err
	}
	if strings.TrimSpace(transport.serverURL) == "" {
		transport.serverURL = config.ServerURL
	}
	if strings.TrimSpace(transport.certFile) == "" {
		transport.certFile = config.CertFile
	}
	if strings.TrimSpace(transport.keyFile) == "" {
		transport.keyFile = config.KeyFile
	}
	if strings.TrimSpace(transport.caFile) == "" {
		transport.caFile = config.CAFile
	}
	if crypto != nil {
		if strings.TrimSpace(crypto.clientID) == "" {
			crypto.clientID = config.ClientID
		}
		if strings.TrimSpace(crypto.cryptoKey) == "" {
			crypto.cryptoKey = config.CryptoKey
		}
	}
	return nil
}

func readClientConfigFile(path string) (clientConfigFile, error) {
	var config clientConfigFile
	if err := readJSONFile(path, &config); err != nil {
		return clientConfigFile{}, err
	}
	return config, nil
}

func validateClientConfigFile(path string) (clientConfigFile, error) {
	config, err := readClientConfigFile(path)
	if err != nil {
		return clientConfigFile{}, err
	}
	if strings.TrimSpace(config.ServerURL) == "" || strings.TrimSpace(config.CertFile) == "" || strings.TrimSpace(config.KeyFile) == "" || strings.TrimSpace(config.CAFile) == "" {
		return clientConfigFile{}, fmt.Errorf("config must define server_url, cert_file, key_file and ca_file")
	}
	parsed, err := url.Parse(config.ServerURL)
	if err != nil || parsed.Scheme != "https" || strings.TrimSpace(parsed.Host) == "" {
		return clientConfigFile{}, fmt.Errorf("config server_url must be an https URL")
	}
	if _, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile); err != nil {
		return clientConfigFile{}, fmt.Errorf("config certificate/key pair is invalid: %w", err)
	}
	if err := validateCACertificateFile(config.CAFile); err != nil {
		return clientConfigFile{}, err
	}
	if strings.TrimSpace(config.CryptoKey) != "" {
		if _, _, err := readPrivateKeyFile(config.CryptoKey); err != nil {
			return clientConfigFile{}, err
		}
	}
	return config, nil
}

func validateCACertificateFile(path string) error {
	body, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read CA certificate: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(body) {
		return fmt.Errorf("CA certificate file does not contain a valid PEM certificate")
	}
	return nil
}

func publishPublicKeyPayload(crypto cryptoFlags) (sdk.PublishClientPublicKeyPayload, error) {
	if strings.TrimSpace(crypto.cryptoKey) == "" && strings.TrimSpace(crypto.clientID) != "" {
		paths, err := defaultClientProfilePaths(crypto.clientID)
		if err != nil {
			return sdk.PublishClientPublicKeyPayload{}, err
		}
		crypto.cryptoKey = paths.CryptoPrivate
	}
	if strings.TrimSpace(crypto.cryptoKey) == "" {
		return sdk.PublishClientPublicKeyPayload{}, fmt.Errorf("--crypto-key is required; pass --client-id for a standard profile, pass --config, or pass --crypto-key explicitly")
	}
	keyFile, privateKey, err := readPrivateKeyFile(crypto.cryptoKey)
	if err != nil {
		return sdk.PublishClientPublicKeyPayload{}, err
	}
	clientID := strings.TrimSpace(crypto.clientID)
	if clientID == "" {
		clientID = keyFile.ClientID
	}
	if clientID == "" {
		return sdk.PublishClientPublicKeyPayload{}, fmt.Errorf("client id is required in --client-id, --config or crypto key file")
	}
	publicKey, err := sdk.DeriveX25519RecipientPublicKey(clientID, privateKey)
	if err != nil {
		return sdk.PublishClientPublicKeyPayload{}, fmt.Errorf("derive public key: %w", err)
	}
	return sdk.PublishClientPublicKeyPayload{Scheme: publicKey.Scheme, PublicKeyB64: base64.StdEncoding.EncodeToString(publicKey.PublicKey), Fingerprint: fingerprint(publicKey.PublicKey)}, nil
}

type staticResolver map[string]sdk.RecipientPublicKey

func (r staticResolver) ResolveRecipientPublicKey(_ context.Context, clientID string) (sdk.RecipientPublicKey, error) {
	key, ok := r[clientID]
	if !ok {
		return sdk.RecipientPublicKey{}, fmt.Errorf("missing recipient public key for %q", clientID)
	}
	return key, nil
}

type serverBackedResolver struct {
	local     staticResolver
	transport *sdk.Client
}

func (r serverBackedResolver) ResolveRecipientPublicKey(ctx context.Context, clientID string) (sdk.RecipientPublicKey, error) {
	if r.local != nil {
		if key, ok := r.local[clientID]; ok {
			return key, nil
		}
	}
	if r.transport == nil {
		return sdk.RecipientPublicKey{}, fmt.Errorf("missing recipient public key for %q", clientID)
	}
	published, err := r.transport.GetClientPublicKeyPayload(clientID)
	if err != nil {
		return sdk.RecipientPublicKey{}, fmt.Errorf("resolve recipient public key for %q: %w", clientID, err)
	}
	return sdk.PublishedClientPublicKeyAsRecipient(published)
}

type staticPrivateKeyProvider struct{ handle sdk.X25519PrivateKeyHandle }

func (p staticPrivateKeyProvider) CurrentPrivateKey(context.Context) (sdk.PrivateKeyHandle, error) {
	return p.handle, nil
}

func writeKeyPair(clientID string, privateKey []byte, privateOut, publicOut string) error {
	privatePayload := privateKeyFile{ClientID: clientID, Scheme: sdk.CryptoEnvelopeHPKEV1, PrivateKeyB64: base64.StdEncoding.EncodeToString(privateKey)}
	if err := writeJSONFileExclusive(privateOut, privatePayload, keyFileMode); err != nil {
		return err
	}
	if err := writePublicKey(clientID, privateKey, publicOut); err != nil {
		_ = os.Remove(privateOut)
		return err
	}
	return nil
}

func writePublicKey(clientID string, privateKey []byte, publicOut string) error {
	publicKey, err := sdk.DeriveX25519RecipientPublicKey(clientID, privateKey)
	if err != nil {
		return fmt.Errorf("derive public key: %w", err)
	}
	payload := publicKeyFile{ClientID: clientID, Scheme: publicKey.Scheme, PublicKeyB64: base64.StdEncoding.EncodeToString(publicKey.PublicKey), Fingerprint: fingerprint(publicKey.PublicKey)}
	return writeJSONFileExclusive(publicOut, payload, publicFileMode)
}

func readPrivateKeyFile(path string) (privateKeyFile, []byte, error) {
	var payload privateKeyFile
	if err := readJSONFile(path, &payload); err != nil {
		return privateKeyFile{}, nil, err
	}
	if payload.Scheme != sdk.CryptoEnvelopeHPKEV1 {
		return privateKeyFile{}, nil, fmt.Errorf("unsupported private key scheme: %s", payload.Scheme)
	}
	privateKey, err := base64.StdEncoding.DecodeString(strings.TrimSpace(payload.PrivateKeyB64))
	if err != nil || len(privateKey) != 32 {
		return privateKeyFile{}, nil, fmt.Errorf("invalid private key file: %s", path)
	}
	if _, err := sdk.NewX25519PrivateKeyHandle(firstNonEmpty(payload.ClientID, "validation"), privateKey); err != nil {
		return privateKeyFile{}, nil, fmt.Errorf("invalid private key file: %w", err)
	}
	return payload, privateKey, nil
}

func readRecipientSpec(spec string) (string, sdk.RecipientPublicKey, bool, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return "", sdk.RecipientPublicKey{}, false, fmt.Errorf("recipient is required")
	}
	clientID := ""
	path := spec
	if left, right, ok := strings.Cut(spec, "="); ok {
		clientID = strings.TrimSpace(left)
		path = strings.TrimSpace(right)
		if clientID == "" {
			return "", sdk.RecipientPublicKey{}, false, fmt.Errorf("recipient client id is required")
		}
		if path == "" {
			return "", sdk.RecipientPublicKey{}, false, fmt.Errorf("recipient public key path is required")
		}
		publicKey, err := readPublicKeyFile(path)
		if err != nil {
			return "", sdk.RecipientPublicKey{}, false, err
		}
		return pinnedRecipientPublicKey(clientID, path, publicKey)
	}
	if model.ValidClientID(spec) && !looksLikePublicKeyPath(spec) {
		return spec, sdk.RecipientPublicKey{}, false, nil
	}
	publicKey, err := readPublicKeyFile(path)
	if err != nil {
		return "", sdk.RecipientPublicKey{}, false, err
	}
	return pinnedRecipientPublicKey(clientID, path, publicKey)
}

func looksLikePublicKeyPath(value string) bool {
	return strings.ContainsAny(value, `/\`) || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".json")
}

func pinnedRecipientPublicKey(clientID, path string, publicKey sdk.RecipientPublicKey) (string, sdk.RecipientPublicKey, bool, error) {
	if clientID == "" {
		clientID = publicKey.ClientID
	}
	if clientID == "" {
		return "", sdk.RecipientPublicKey{}, false, fmt.Errorf("recipient client id is required for %s", path)
	}
	if publicKey.ClientID != "" && publicKey.ClientID != clientID {
		return "", sdk.RecipientPublicKey{}, false, fmt.Errorf("recipient id %q does not match public key client id %q", clientID, publicKey.ClientID)
	}
	publicKey.ClientID = clientID
	return clientID, publicKey, true, nil
}

func readPublicKeyFile(path string) (sdk.RecipientPublicKey, error) {
	var payload publicKeyFile
	if err := readJSONFile(path, &payload); err != nil {
		return sdk.RecipientPublicKey{}, err
	}
	if payload.Scheme != sdk.CryptoEnvelopeHPKEV1 {
		return sdk.RecipientPublicKey{}, fmt.Errorf("unsupported public key scheme: %s", payload.Scheme)
	}
	publicKey, err := base64.StdEncoding.DecodeString(strings.TrimSpace(payload.PublicKeyB64))
	if err != nil || len(publicKey) != 32 {
		return sdk.RecipientPublicKey{}, fmt.Errorf("invalid public key file: %s", path)
	}
	return sdk.RecipientPublicKey{ClientID: payload.ClientID, Scheme: payload.Scheme, PublicKey: publicKey, Fingerprint: payload.Fingerprint}, nil
}

func readJSONFile(path string, target any) error {
	body, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if err := json.Unmarshal(body, target); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	return nil
}

func writeJSONFileExclusive(path string, value any, mode os.FileMode) error {
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	return writeExclusive(path, body, mode)
}

func writeOutput(stdout io.Writer, path string, body []byte, mode os.FileMode) error {
	if path == "-" {
		_, err := stdout.Write(body)
		return err
	}
	return writeExclusive(path, body, mode)
}

func writeExclusive(path string, body []byte, mode os.FileMode) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("output path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && filepath.Dir(path) != "." {
		return fmt.Errorf("create output directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if _, err := file.Write(body); err != nil {
		if closeErr := file.Close(); closeErr != nil {
			return fmt.Errorf("write %s: %w", path, errors.Join(err, closeErr))
		}
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close %s: %w", path, err)
	}
	return nil
}

func writeJSON(w io.Writer, value any) int {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		fmt.Fprintf(os.Stderr, "write json: %v\n", err)
		return 1
	}
	return 0
}

func fingerprint(publicKey []byte) string {
	sum := sha256.Sum256(publicKey)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func envDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

var _ sdk.Clock = fixedClock{}

type fixedClock struct{}

func (fixedClock) Now() time.Time { return time.Unix(0, 0).UTC() }
