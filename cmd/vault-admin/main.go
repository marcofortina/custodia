package main

import (
	"bytes"
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
	case "status read":
		err = requestJSON(&cfg, http.MethodGet, "/v1/status", nil, os.Stdout)
	case "client whoami":
		err = requestJSON(&cfg, http.MethodGet, "/v1/me", nil, os.Stdout)
	case "client list":
		err = requestJSON(&cfg, http.MethodGet, "/v1/clients", nil, os.Stdout)
	case "client get":
		err = runClientGet(&cfg, args[2:])
	case "client create":
		err = runClientCreate(&cfg, args[2:])
	case "client revoke":
		err = runClientRevoke(&cfg, args[2:])
	case "audit list":
		err = runAuditList(&cfg, args[2:])
	case "audit export":
		err = runAuditExport(&cfg, args[2:])
	case "audit verify":
		err = runAuditVerify(&cfg, args[2:])
	case "secret versions":
		err = runSecretVersions(&cfg, args[2:])
	case "access list":
		err = runAccessList(&cfg, args[2:])
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

func runClientGet(cfg *cliConfig, args []string) error {
	cmd := flag.NewFlagSet("client get", flag.ExitOnError)
	clientID := cmd.String("client-id", "", "client id to read")
	_ = cmd.Parse(args)
	if *clientID == "" {
		return fmt.Errorf("--client-id is required")
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
	_ = cmd.Parse(args)
	if *limit <= 0 || *limit > 500 {
		return fmt.Errorf("--limit must be between 1 and 500")
	}
	return requestJSON(cfg, http.MethodGet, fmt.Sprintf("/v1/audit-events/export?limit=%d", *limit), nil, os.Stdout)
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
	_ = cmd.Parse(args)
	if *secretID == "" {
		return fmt.Errorf("--secret-id is required")
	}
	return requestJSON(cfg, http.MethodGet, "/v1/secrets/"+pathEscape(*secretID)+"/versions", nil, os.Stdout)
}

func runAccessList(cfg *cliConfig, args []string) error {
	cmd := flag.NewFlagSet("access list", flag.ExitOnError)
	secretID := cmd.String("secret-id", "", "secret id")
	_ = cmd.Parse(args)
	if *secretID == "" {
		return fmt.Errorf("--secret-id is required")
	}
	return requestJSON(cfg, http.MethodGet, "/v1/secrets/"+pathEscape(*secretID)+"/access", nil, os.Stdout)
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
	path := "/v1/secrets/" + pathEscape(*secretID) + "/access/" + pathEscape(*clientID)
	return requestJSON(cfg, http.MethodDelete, path, nil, os.Stdout)
}

func addQueryFilter(query url.Values, key string, value string) {
	if strings.TrimSpace(value) != "" {
		query.Set(key, strings.TrimSpace(value))
	}
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
  vault-admin [global flags] status read
  vault-admin [global flags] client whoami
  vault-admin [global flags] client list
  vault-admin [global flags] client get --client-id ID
  vault-admin [global flags] client create --client-id ID --mtls-subject SUBJECT
  vault-admin [global flags] client revoke --client-id ID [--reason REASON]
  vault-admin [global flags] audit list [--limit N] [--outcome STATUS] [--action ACTION]
  vault-admin [global flags] audit export [--limit N]
  vault-admin [global flags] audit verify [--limit N]
  vault-admin [global flags] secret versions --secret-id ID
  vault-admin [global flags] access list --secret-id ID
  vault-admin [global flags] access grant-request --secret-id ID --client-id ID --permissions read[,write,share]
  vault-admin [global flags] access activate --secret-id ID --client-id ID --envelope-file FILE
  vault-admin [global flags] access revoke --secret-id ID --client-id ID

global flags:
  --server-url URL
  --cert FILE
  --key FILE
  --ca FILE`)
}
