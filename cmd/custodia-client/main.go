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
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"custodia/internal/build"

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
	serverURL string
	certFile  string
	keyFile   string
	caFile    string
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
  custodia-client key generate --client-id ID --private-key-out FILE --public-key-out FILE
  custodia-client key public --client-id ID --private-key FILE --public-key-out FILE
  custodia-client secret put --server-url URL --cert FILE --key FILE --ca FILE --client-id ID --crypto-key FILE --name NAME --value-file FILE [--recipient ID=PUBLIC.json]
  custodia-client secret get --server-url URL --cert FILE --key FILE --ca FILE --client-id ID --crypto-key FILE --secret-id ID [--out FILE]
  custodia-client secret share --server-url URL --cert FILE --key FILE --ca FILE --client-id ID --crypto-key FILE --secret-id ID --target-client-id ID --recipient ID=PUBLIC.json
  custodia-client secret version put --server-url URL --cert FILE --key FILE --ca FILE --client-id ID --crypto-key FILE --secret-id ID --value-file FILE [--recipient ID=PUBLIC.json]
  custodia-client secret list --server-url URL --cert FILE --key FILE --ca FILE [--limit N]

Secret payloads are encrypted/decrypted locally. Custodia receives only ciphertext, crypto_metadata and opaque recipient envelopes.`)
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
	if strings.TrimSpace(*clientID) == "" || strings.TrimSpace(*privateOut) == "" || strings.TrimSpace(*publicOut) == "" {
		fmt.Fprintln(a.stderr, "--client-id, --private-key-out and --public-key-out are required")
		return 2
	}
	privateKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, privateKey); err != nil {
		fmt.Fprintf(a.stderr, "generate private key: %v\n", err)
		return 1
	}
	if err := writeKeyPair(*clientID, privateKey, *privateOut, *publicOut); err != nil {
		fmt.Fprintf(a.stderr, "%v\n", err)
		return 1
	}
	fmt.Fprintf(a.stdout, "wrote %s and %s\n", *privateOut, *publicOut)
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
	case "version":
		return a.runSecretVersion(args[1:])
	case "list":
		return a.runSecretList(args[1:])
	default:
		fmt.Fprintf(a.stderr, "unknown secret subcommand: %s\n", args[0])
		return 2
	}
}

func (a *app) runSecretPut(args []string) int {
	fs := newFlagSet("custodia-client secret put", a.stderr)
	transport := registerTransportFlags(fs)
	crypto := registerCryptoFlags(fs)
	name := fs.String("name", "", "secret name")
	valueFile := fs.String("value-file", "", "plaintext file to encrypt locally")
	permissions := fs.Int("permissions", defaultPermissions, "permission bitmask for recipients")
	if !parseFlags(fs, args, a.stderr) {
		return 2
	}
	if strings.TrimSpace(*name) == "" || strings.TrimSpace(*valueFile) == "" {
		fmt.Fprintln(a.stderr, "--name and --value-file are required")
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
		Name:        *name,
		Plaintext:   plaintext,
		Recipients:  recipients,
		Permissions: *permissions,
	})
	if err != nil {
		fmt.Fprintf(a.stderr, "create encrypted secret: %v\n", err)
		return 1
	}
	return writeJSON(a.stdout, ref)
}

func (a *app) runSecretGet(args []string) int {
	fs := newFlagSet("custodia-client secret get", a.stderr)
	transport := registerTransportFlags(fs)
	crypto := registerCryptoFlagsNoRecipients(fs)
	secretID := fs.String("secret-id", "", "secret id")
	out := fs.String("out", "-", "plaintext output file or - for stdout")
	if !parseFlags(fs, args, a.stderr) {
		return 2
	}
	if strings.TrimSpace(*secretID) == "" {
		fmt.Fprintln(a.stderr, "--secret-id is required")
		return 2
	}
	cryptoClient, _, err := buildCryptoClient(transport, crypto)
	if err != nil {
		fmt.Fprintf(a.stderr, "%v\n", err)
		return 1
	}
	secret, err := cryptoClient.ReadDecryptedSecret(context.Background(), *secretID)
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

func (a *app) runSecretShare(args []string) int {
	fs := newFlagSet("custodia-client secret share", a.stderr)
	transport := registerTransportFlags(fs)
	crypto := registerCryptoFlags(fs)
	secretID := fs.String("secret-id", "", "secret id")
	targetClientID := fs.String("target-client-id", "", "target recipient client id")
	permissions := fs.Int("permissions", defaultSharePerms, "target permission bitmask")
	if !parseFlags(fs, args, a.stderr) {
		return 2
	}
	if strings.TrimSpace(*secretID) == "" || strings.TrimSpace(*targetClientID) == "" {
		fmt.Fprintln(a.stderr, "--secret-id and --target-client-id are required")
		return 2
	}
	cryptoClient, _, err := buildCryptoClient(transport, crypto)
	if err != nil {
		fmt.Fprintf(a.stderr, "%v\n", err)
		return 1
	}
	if err := cryptoClient.ShareEncryptedSecret(context.Background(), *secretID, sdk.ShareEncryptedSecretRequest{TargetClientID: *targetClientID, Permissions: *permissions}); err != nil {
		fmt.Fprintf(a.stderr, "share encrypted secret: %v\n", err)
		return 1
	}
	return writeJSON(a.stdout, map[string]string{"secret_id": *secretID, "target_client_id": *targetClientID, "status": "shared"})
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
	fs := newFlagSet("custodia-client secret version put", a.stderr)
	transport := registerTransportFlags(fs)
	crypto := registerCryptoFlags(fs)
	secretID := fs.String("secret-id", "", "secret id")
	valueFile := fs.String("value-file", "", "plaintext file to encrypt locally")
	permissions := fs.Int("permissions", defaultPermissions, "permission bitmask for recipients")
	if !parseFlags(fs, args, a.stderr) {
		return 2
	}
	if strings.TrimSpace(*secretID) == "" || strings.TrimSpace(*valueFile) == "" {
		fmt.Fprintln(a.stderr, "--secret-id and --value-file are required")
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
	ref, err := cryptoClient.CreateEncryptedSecretVersion(context.Background(), *secretID, sdk.CreateEncryptedSecretVersionRequest{Plaintext: plaintext, Recipients: recipients, Permissions: *permissions})
	if err != nil {
		fmt.Fprintf(a.stderr, "create encrypted secret version: %v\n", err)
		return 1
	}
	return writeJSON(a.stdout, ref)
}

func (a *app) runSecretList(args []string) int {
	fs := newFlagSet("custodia-client secret list", a.stderr)
	transport := registerTransportFlags(fs)
	limit := fs.Int("limit", 100, "maximum rows to return")
	if !parseFlags(fs, args, a.stderr) {
		return 2
	}
	client, err := sdk.New(sdk.Config{ServerURL: transport.serverURL, CertFile: transport.certFile, KeyFile: transport.keyFile, CAFile: transport.caFile})
	if err != nil {
		fmt.Fprintf(a.stderr, "create transport client: %v\n", err)
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

func registerTransportFlags(fs *flag.FlagSet) transportFlags {
	var flags transportFlags
	fs.StringVar(&flags.serverURL, "server-url", envDefault("CUSTODIA_BASE_URL", ""), "Custodia API base URL")
	fs.StringVar(&flags.certFile, "cert", envDefault("CUSTODIA_CLIENT_CERT", ""), "mTLS client certificate")
	fs.StringVar(&flags.keyFile, "key", envDefault("CUSTODIA_CLIENT_KEY", ""), "mTLS client private key")
	fs.StringVar(&flags.caFile, "ca", envDefault("CUSTODIA_CA_CERT", ""), "Custodia CA certificate")
	return flags
}

func registerCryptoFlags(fs *flag.FlagSet) cryptoFlags {
	flags := registerCryptoFlagsNoRecipients(fs)
	fs.Var(&flags.recipients, "recipient", "recipient public key file, either ID=FILE or FILE")
	return flags
}

func registerCryptoFlagsNoRecipients(fs *flag.FlagSet) cryptoFlags {
	var flags cryptoFlags
	fs.StringVar(&flags.clientID, "client-id", envDefault("CUSTODIA_CLIENT_ID", ""), "local client id")
	fs.StringVar(&flags.cryptoKey, "crypto-key", envDefault("CUSTODIA_CRYPTO_KEY", ""), "local X25519 private key JSON")
	return flags
}

func buildCryptoClient(transport transportFlags, crypto cryptoFlags) (*sdk.CryptoClient, []string, error) {
	if strings.TrimSpace(transport.serverURL) == "" || strings.TrimSpace(transport.certFile) == "" || strings.TrimSpace(transport.keyFile) == "" || strings.TrimSpace(transport.caFile) == "" {
		return nil, nil, fmt.Errorf("--server-url, --cert, --key and --ca are required")
	}
	if strings.TrimSpace(crypto.cryptoKey) == "" {
		return nil, nil, fmt.Errorf("--crypto-key is required")
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
		recipientID, publicKey, err := readRecipientSpec(spec)
		if err != nil {
			return nil, nil, err
		}
		publicKeys[recipientID] = publicKey
		recipientIDs = append(recipientIDs, recipientID)
	}
	transportClient, err := sdk.New(sdk.Config{ServerURL: transport.serverURL, CertFile: transport.certFile, KeyFile: transport.keyFile, CAFile: transport.caFile})
	if err != nil {
		return nil, nil, fmt.Errorf("create transport client: %w", err)
	}
	cryptoClient, err := transportClient.WithCrypto(sdk.CryptoOptions{PublicKeyResolver: staticResolver(publicKeys), PrivateKeyProvider: staticPrivateKeyProvider{handle: handle}, RandomSource: rand.Reader, Clock: sdk.SystemClock{}})
	if err != nil {
		return nil, nil, fmt.Errorf("create crypto client: %w", err)
	}
	return cryptoClient, recipientIDs, nil
}

type staticResolver map[string]sdk.RecipientPublicKey

func (r staticResolver) ResolveRecipientPublicKey(_ context.Context, clientID string) (sdk.RecipientPublicKey, error) {
	key, ok := r[clientID]
	if !ok {
		return sdk.RecipientPublicKey{}, fmt.Errorf("missing recipient public key for %q", clientID)
	}
	return key, nil
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

func readRecipientSpec(spec string) (string, sdk.RecipientPublicKey, error) {
	clientID := ""
	path := spec
	if left, right, ok := strings.Cut(spec, "="); ok {
		clientID = strings.TrimSpace(left)
		path = strings.TrimSpace(right)
	}
	if path == "" {
		return "", sdk.RecipientPublicKey{}, fmt.Errorf("recipient public key path is required")
	}
	publicKey, err := readPublicKeyFile(path)
	if err != nil {
		return "", sdk.RecipientPublicKey{}, err
	}
	if clientID == "" {
		clientID = publicKey.ClientID
	}
	if clientID == "" {
		return "", sdk.RecipientPublicKey{}, fmt.Errorf("recipient client id is required for %s", path)
	}
	if publicKey.ClientID != "" && publicKey.ClientID != clientID {
		return "", sdk.RecipientPublicKey{}, fmt.Errorf("recipient id %q does not match public key client id %q", clientID, publicKey.ClientID)
	}
	publicKey.ClientID = clientID
	return clientID, publicKey, nil
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
	defer file.Close()
	if _, err := file.Write(body); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
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
