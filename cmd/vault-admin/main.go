package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"custodia/internal/model"
	"custodia/internal/mtls"
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
	if len(args) < 2 {
		usage()
		os.Exit(2)
	}

	var err error
	switch args[0] + " " + args[1] {
	case "client list":
		err = requestJSON(&cfg, http.MethodGet, "/v1/clients", nil, os.Stdout)
	case "client create":
		err = runClientCreate(&cfg, args[2:])
	case "client revoke":
		err = runClientRevoke(&cfg, args[2:])
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

func runClientCreate(cfg *cliConfig, args []string) error {
	cmd := flag.NewFlagSet("client create", flag.ExitOnError)
	req := model.CreateClientRequest{}
	cmd.StringVar(&req.ClientID, "client-id", "", "client id to register")
	cmd.StringVar(&req.MTLSSubject, "mtls-subject", "", "certificate SAN/CN mapped to the client id")
	_ = cmd.Parse(args)
	if req.ClientID == "" || req.MTLSSubject == "" {
		return fmt.Errorf("--client-id and --mtls-subject are required")
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
	return requestJSON(cfg, http.MethodPost, "/v1/clients/revoke", req, os.Stdout)
}

func runAccessGrantRequest(cfg *cliConfig, args []string) error {
	cmd := flag.NewFlagSet("access grant-request", flag.ExitOnError)
	secretID := cmd.String("secret-id", "", "secret id")
	clientID := cmd.String("client-id", "", "client id")
	versionID := cmd.String("version-id", "", "secret version id; defaults to latest active version")
	permissions := cmd.String("permissions", "", "permission bits or names: read, write, share, all")
	_ = cmd.Parse(args)
	if *secretID == "" || *clientID == "" || *permissions == "" {
		return fmt.Errorf("--secret-id, --client-id and --permissions are required")
	}
	bits, err := parsePermissionBits(*permissions)
	if err != nil {
		return err
	}
	req := model.AccessGrantRequest{VersionID: *versionID, TargetClientID: *clientID, Permissions: bits}
	return requestJSON(cfg, http.MethodPost, fmt.Sprintf("/v1/secrets/%s/access-requests", *secretID), req, os.Stdout)
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
	envelope, err := os.ReadFile(*envelopeFile)
	if err != nil {
		return err
	}
	req := model.ActivateAccessRequest{Envelope: strings.TrimSpace(string(envelope))}
	path := fmt.Sprintf("/v1/secrets/%s/access/%s/activate", *secretID, *clientID)
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
	path := fmt.Sprintf("/v1/secrets/%s/access/%s", *secretID, *clientID)
	return requestJSON(cfg, http.MethodDelete, path, nil, os.Stdout)
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
	client, err := httpClient(cfg)
	if err != nil {
		return err
	}
	var body io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		body = bytes.NewReader(encoded)
	}
	req, err := http.NewRequest(method, cfg.serverURL+path, body)
	if err != nil {
		return err
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode > 299 {
		responseBody, _ := io.ReadAll(res.Body)
		return fmt.Errorf("request failed: %s: %s", res.Status, string(responseBody))
	}
	_, err = io.Copy(out, res.Body)
	return err
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
  vault-admin [global flags] client list
  vault-admin [global flags] client create --client-id ID --mtls-subject SUBJECT
  vault-admin [global flags] client revoke --client-id ID [--reason REASON]
  vault-admin [global flags] access grant-request --secret-id ID --client-id ID --permissions read[,write,share]
  vault-admin [global flags] access activate --secret-id ID --client-id ID --envelope-file FILE
  vault-admin [global flags] access revoke --secret-id ID --client-id ID

global flags:
  --server-url URL
  --cert FILE
  --key FILE
  --ca FILE`)
}
