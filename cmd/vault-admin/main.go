package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
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
	case "client revoke":
		err = runClientRevoke(&cfg, args[2:])
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
  vault-admin [global flags] client revoke --client-id ID [--reason REASON]
  vault-admin [global flags] access revoke --secret-id ID --client-id ID

global flags:
  --server-url URL
  --cert FILE
  --key FILE
  --ca FILE`)
}
