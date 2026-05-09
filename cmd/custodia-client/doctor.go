// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/url"
	"strings"

	sdk "custodia/pkg/client"
)

const (
	clientDoctorOK   = "OK"
	clientDoctorWarn = "WARN"
	clientDoctorFail = "FAIL"
)

type clientDoctorFinding struct {
	Status  string
	Name    string
	Message string
	Hint    string
}

type clientDoctorOptions struct {
	configFile string
	online     bool
	out        io.Writer
}

func (a *app) runDoctor(args []string) int {
	fs := newFlagSet("custodia-client doctor", a.stderr)
	configFile := fs.String("config", envDefault("CUSTODIA_CLIENT_CONFIG", ""), "Custodia client config JSON")
	online := fs.Bool("online", false, "also contact the configured Custodia server")
	if !parseFlags(fs, args, a.stderr) {
		return 2
	}
	if strings.TrimSpace(*configFile) == "" {
		fmt.Fprintln(a.stderr, "--config is required")
		return 2
	}
	findings := collectClientDoctorFindings(clientDoctorOptions{configFile: *configFile, online: *online, out: a.stdout})
	writeClientDoctorFindings(a.stdout, findings)
	if clientDoctorHasFailure(findings) {
		return 1
	}
	return 0
}

func collectClientDoctorFindings(opts clientDoctorOptions) []clientDoctorFinding {
	findings := []clientDoctorFinding{}
	configPath := strings.TrimSpace(opts.configFile)
	config, err := readClientConfigFile(configPath)
	if err != nil {
		return append(findings, clientDoctorFinding{Status: clientDoctorFail, Name: "client config", Message: err.Error()})
	}
	findings = append(findings, clientDoctorFinding{Status: clientDoctorOK, Name: "client config", Message: configPath})
	findings = append(findings, checkClientDoctorServerURL(config.ServerURL))
	findings = append(findings, checkClientDoctorTLSKeyPair(config.CertFile, config.KeyFile))
	findings = append(findings, checkClientDoctorCA(config.CAFile))
	if strings.TrimSpace(config.ClientID) == "" {
		findings = append(findings, clientDoctorFinding{Status: clientDoctorWarn, Name: "client id", Message: "not configured"})
	} else {
		findings = append(findings, clientDoctorFinding{Status: clientDoctorOK, Name: "client id", Message: config.ClientID})
	}
	findings = append(findings, checkClientDoctorCryptoKey(config.CryptoKey)...)
	if opts.online {
		findings = append(findings, checkClientDoctorOnline(configPath))
	} else {
		findings = append(findings, clientDoctorFinding{Status: clientDoctorWarn, Name: "online server check", Message: "skipped", Hint: "pass --online to test mTLS reachability"})
	}
	return findings
}

func checkClientDoctorServerURL(serverURL string) clientDoctorFinding {
	parsed, err := url.Parse(strings.TrimSpace(serverURL))
	if err != nil || parsed.Scheme != "https" || strings.TrimSpace(parsed.Host) == "" {
		return clientDoctorFinding{Status: clientDoctorFail, Name: "server URL", Message: "must be an https URL"}
	}
	return clientDoctorFinding{Status: clientDoctorOK, Name: "server URL", Message: serverURL}
}

func checkClientDoctorTLSKeyPair(certFile, keyFile string) clientDoctorFinding {
	if strings.TrimSpace(certFile) == "" || strings.TrimSpace(keyFile) == "" {
		return clientDoctorFinding{Status: clientDoctorFail, Name: "mTLS certificate/key", Message: "cert_file and key_file are required"}
	}
	if _, err := tls.LoadX509KeyPair(certFile, keyFile); err != nil {
		return clientDoctorFinding{Status: clientDoctorFail, Name: "mTLS certificate/key", Message: err.Error()}
	}
	return clientDoctorFinding{Status: clientDoctorOK, Name: "mTLS certificate/key", Message: certFile + " + " + keyFile}
}

func checkClientDoctorCA(caFile string) clientDoctorFinding {
	if strings.TrimSpace(caFile) == "" {
		return clientDoctorFinding{Status: clientDoctorFail, Name: "CA bundle", Message: "ca_file is required"}
	}
	if err := validateCACertificateFile(caFile); err != nil {
		return clientDoctorFinding{Status: clientDoctorFail, Name: "CA bundle", Message: err.Error()}
	}
	return clientDoctorFinding{Status: clientDoctorOK, Name: "CA bundle", Message: caFile}
}

func checkClientDoctorCryptoKey(cryptoKey string) []clientDoctorFinding {
	cryptoKey = strings.TrimSpace(cryptoKey)
	if cryptoKey == "" {
		return []clientDoctorFinding{{Status: clientDoctorWarn, Name: "local crypto key", Message: "not configured", Hint: "encrypted put/get requires --crypto-key or config.crypto_key"}}
	}
	payload, privateKey, err := readPrivateKeyFile(cryptoKey)
	if err != nil {
		return []clientDoctorFinding{{Status: clientDoctorFail, Name: "local crypto key", Message: err.Error()}}
	}
	publicKey, err := sdk.DeriveX25519RecipientPublicKey(firstNonEmpty(payload.ClientID, "validation"), privateKey)
	if err != nil {
		return []clientDoctorFinding{{Status: clientDoctorFail, Name: "local crypto key", Message: err.Error()}}
	}
	return []clientDoctorFinding{
		{Status: clientDoctorOK, Name: "local crypto key", Message: cryptoKey},
		{Status: clientDoctorOK, Name: "derived public key", Message: fingerprint(publicKey.PublicKey)},
	}
}

func checkClientDoctorOnline(configPath string) clientDoctorFinding {
	client, err := buildTransportClient(transportFlags{configFile: configPath})
	if err != nil {
		return clientDoctorFinding{Status: clientDoctorFail, Name: "online server check", Message: err.Error()}
	}
	info, err := client.CurrentClientInfo()
	if err != nil {
		return clientDoctorFinding{Status: clientDoctorFail, Name: "online server check", Message: err.Error()}
	}
	message := strings.TrimSpace(info.ClientID)
	if message == "" {
		message = "reachable"
	}
	return clientDoctorFinding{Status: clientDoctorOK, Name: "online server check", Message: message}
}

func writeClientDoctorFindings(out io.Writer, findings []clientDoctorFinding) {
	if out == nil {
		out = io.Discard
	}
	fmt.Fprintln(out, "Custodia client doctor")
	fmt.Fprintln(out)
	for _, finding := range findings {
		fmt.Fprintf(out, "[%s] %s: %s\n", finding.Status, finding.Name, finding.Message)
		if finding.Hint != "" {
			fmt.Fprintf(out, "      Hint: %s\n", finding.Hint)
		}
	}
	fmt.Fprintln(out)
	if clientDoctorHasFailure(findings) {
		fmt.Fprintln(out, "Result: failed")
		return
	}
	if clientDoctorHasWarning(findings) {
		fmt.Fprintln(out, "Result: warning")
		return
	}
	fmt.Fprintln(out, "Result: ok")
}

func clientDoctorHasFailure(findings []clientDoctorFinding) bool {
	for _, finding := range findings {
		if finding.Status == clientDoctorFail {
			return true
		}
	}
	return false
}

func clientDoctorHasWarning(findings []clientDoctorFinding) bool {
	for _, finding := range findings {
		if finding.Status == clientDoctorWarn {
			return true
		}
	}
	return false
}
