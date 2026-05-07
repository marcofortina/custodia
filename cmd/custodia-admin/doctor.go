// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	serverconfig "custodia/internal/config"

	"gopkg.in/yaml.v3"
)

const (
	doctorOK   = "OK"
	doctorWarn = "WARN"
	doctorFail = "FAIL"
)

type doctorFinding struct {
	Status  string
	Name    string
	Message string
	Hint    string
}

type doctorSignerConfig struct {
	Addr                string
	TLSCertFile         string
	TLSKeyFile          string
	ClientCAFile        string
	CACertFile          string
	CAKeyFile           string
	CAKeyPassphraseFile string
	KeyProvider         string
	PKCS11SignCommand   string
	AdminSubjects       []string
	CRLFile             string
	AuditLogFile        string
}

type doctorOptions struct {
	serverConfig string
	signerConfig string
	systemd      bool
	network      bool
	serverUnit   string
	signerUnit   string
	out          io.Writer
}

func runDoctor(args []string) error {
	cmd := flag.NewFlagSet("doctor", flag.ExitOnError)
	serverConfig := cmd.String("server-config", "/etc/custodia/custodia-server.yaml", "custodia-server YAML config")
	signerConfig := cmd.String("signer-config", "/etc/custodia/custodia-signer.yaml", "custodia-signer YAML config")
	systemd := cmd.Bool("systemd", false, "check custodia systemd unit status")
	network := cmd.Bool("network", false, "check configured local TCP listeners")
	serverUnit := cmd.String("server-unit", "custodia-server.service", "custodia-server systemd unit")
	signerUnit := cmd.String("signer-unit", "custodia-signer.service", "custodia-signer systemd unit")
	_ = cmd.Parse(args)
	return runDoctorWithOptions(doctorOptions{serverConfig: *serverConfig, signerConfig: *signerConfig, systemd: *systemd, network: *network, serverUnit: *serverUnit, signerUnit: *signerUnit, out: os.Stdout})
}

func runDoctorWithOptions(opts doctorOptions) error {
	if opts.out == nil {
		opts.out = io.Discard
	}
	findings := collectDoctorOfflineFindings(strings.TrimSpace(opts.serverConfig), strings.TrimSpace(opts.signerConfig))
	if opts.systemd {
		findings = append(findings, collectDoctorSystemdFindings(opts.serverUnit, opts.signerUnit)...)
	}
	if opts.network {
		findings = append(findings, collectDoctorNetworkFindings(strings.TrimSpace(opts.serverConfig), strings.TrimSpace(opts.signerConfig))...)
	}
	writeDoctorFindings(opts.out, findings)
	if doctorHasFailure(findings) {
		return fmt.Errorf("doctor failed")
	}
	return nil
}

func collectDoctorOfflineFindings(serverConfigPath, signerConfigPath string) []doctorFinding {
	findings := []doctorFinding{}
	serverConfigPath = strings.TrimSpace(serverConfigPath)
	if serverConfigPath == "" {
		findings = append(findings, doctorFinding{Status: doctorFail, Name: "server config", Message: "--server-config is required"})
	} else {
		findings = append(findings, checkReadableFile("server config", serverConfigPath, false, true))
		cfg, err := serverconfig.LoadFile(serverConfigPath)
		if err != nil {
			findings = append(findings, doctorFinding{Status: doctorFail, Name: "server config parse", Message: err.Error()})
		} else {
			findings = append(findings, serverConfigFindings(cfg)...)
		}
	}

	signerConfigPath = strings.TrimSpace(signerConfigPath)
	if signerConfigPath == "" {
		findings = append(findings, doctorFinding{Status: doctorFail, Name: "signer config", Message: "--signer-config is required"})
	} else {
		findings = append(findings, checkReadableFile("signer config", signerConfigPath, false, true))
		cfg, err := loadDoctorSignerConfig(signerConfigPath)
		if err != nil {
			findings = append(findings, doctorFinding{Status: doctorFail, Name: "signer config parse", Message: err.Error()})
		} else {
			findings = append(findings, signerConfigFindings(cfg)...)
		}
	}
	return findings
}

func collectDoctorSystemdFindings(serverUnit, signerUnit string) []doctorFinding {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return []doctorFinding{{Status: doctorWarn, Name: "systemd", Message: "systemctl not available"}}
	}
	serverUnit = strings.TrimSpace(serverUnit)
	if serverUnit == "" {
		serverUnit = "custodia-server.service"
	}
	signerUnit = strings.TrimSpace(signerUnit)
	if signerUnit == "" {
		signerUnit = "custodia-signer.service"
	}
	return []doctorFinding{
		checkSystemdUnit("server unit", serverUnit),
		checkSystemdUnit("signer unit", signerUnit),
	}
}

func checkSystemdUnit(name, unit string) doctorFinding {
	active := exec.Command("systemctl", "is-active", "--quiet", unit).Run()
	if active != nil {
		return doctorFinding{Status: doctorFail, Name: name, Message: unit + " is not active", Hint: "run: systemctl status " + unit + " --no-pager"}
	}
	enabled := exec.Command("systemctl", "is-enabled", "--quiet", unit).Run()
	if enabled != nil {
		return doctorFinding{Status: doctorWarn, Name: name, Message: unit + " is active but not enabled"}
	}
	return doctorFinding{Status: doctorOK, Name: name, Message: unit + " active/enabled"}
}

func collectDoctorNetworkFindings(serverConfigPath, signerConfigPath string) []doctorFinding {
	findings := []doctorFinding{}
	if serverConfigPath != "" {
		cfg, err := serverconfig.LoadFile(serverConfigPath)
		if err != nil {
			findings = append(findings, doctorFinding{Status: doctorFail, Name: "server network config", Message: err.Error()})
		} else {
			findings = append(findings, checkTCPListener("server API listener", cfg.APIAddr))
			if strings.TrimSpace(cfg.WebAddr) != "" {
				findings = append(findings, checkTCPListener("server web listener", cfg.WebAddr))
			}
		}
	}
	if signerConfigPath != "" {
		cfg, err := loadDoctorSignerConfig(signerConfigPath)
		if err != nil {
			findings = append(findings, doctorFinding{Status: doctorFail, Name: "signer network config", Message: err.Error()})
		} else {
			findings = append(findings, checkTCPListener("signer listener", cfg.Addr))
		}
	}
	return findings
}

func checkTCPListener(name, addr string) doctorFinding {
	dialAddr, err := normalizeDoctorDialAddr(addr)
	if err != nil {
		return doctorFinding{Status: doctorFail, Name: name, Message: err.Error()}
	}
	conn, err := net.DialTimeout("tcp", dialAddr, 2*time.Second)
	if err != nil {
		return doctorFinding{Status: doctorFail, Name: name, Message: fmt.Sprintf("%s: %v", dialAddr, err)}
	}
	_ = conn.Close()
	return doctorFinding{Status: doctorOK, Name: name, Message: dialAddr}
}

func normalizeDoctorDialAddr(addr string) (string, error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", fmt.Errorf("listener address is empty")
	}
	if strings.HasPrefix(addr, ":") {
		return "127.0.0.1" + addr, nil
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(host) == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port), nil
}

func serverConfigFindings(cfg serverconfig.Config) []doctorFinding {
	findings := []doctorFinding{
		{Status: doctorOK, Name: "server profile", Message: cfg.Profile},
		{Status: doctorOK, Name: "server storage backend", Message: cfg.StoreBackend},
	}
	profile := strings.ToLower(strings.TrimSpace(cfg.Profile))
	backend := strings.ToLower(strings.TrimSpace(cfg.StoreBackend))
	switch {
	case profile == serverconfig.ProfileLite && backend != "sqlite":
		findings = append(findings, doctorFinding{Status: doctorFail, Name: "server profile/backend", Message: "lite profile should use sqlite storage"})
	case profile == serverconfig.ProfileFull && backend != "postgres":
		findings = append(findings, doctorFinding{Status: doctorFail, Name: "server profile/backend", Message: "full profile should use postgres storage"})
	default:
		findings = append(findings, doctorFinding{Status: doctorOK, Name: "server profile/backend", Message: "coherent"})
	}
	if backend == "sqlite" {
		findings = append(findings, checkSQLiteDatabaseURL(cfg.DatabaseURL))
	}
	if backend == "postgres" {
		findings = append(findings, checkPostgresDatabaseURL(cfg.DatabaseURL))
	}
	findings = append(findings,
		checkReadableFile("server TLS certificate", cfg.TLSCertFile, false, true),
		checkReadableFile("server TLS key", cfg.TLSKeyFile, true, true),
		checkReadableFile("server client CA", cfg.ClientCAFile, false, true),
		checkReadableFile("server client CRL", cfg.ClientCRLFile, false, false),
		checkLogDirectory("server log directory", cfg.LogFile),
	)
	if !cfg.WebMFARequired {
		findings = append(findings, doctorFinding{Status: doctorWarn, Name: "web MFA", Message: "web MFA is not required", Hint: "set web.mfa_required: true for operator consoles"})
	} else {
		findings = append(findings, doctorFinding{Status: doctorOK, Name: "web MFA", Message: "required"})
	}
	return findings
}

func signerConfigFindings(cfg doctorSignerConfig) []doctorFinding {
	findings := []doctorFinding{
		{Status: doctorOK, Name: "signer address", Message: cfg.Addr},
	}
	if strings.TrimSpace(cfg.Addr) == "" {
		findings[len(findings)-1] = doctorFinding{Status: doctorFail, Name: "signer address", Message: "empty"}
	}
	if len(cfg.AdminSubjects) == 0 {
		findings = append(findings, doctorFinding{Status: doctorFail, Name: "signer admin subjects", Message: "no admin subject configured"})
	} else {
		findings = append(findings, doctorFinding{Status: doctorOK, Name: "signer admin subjects", Message: strings.Join(cfg.AdminSubjects, ",")})
	}
	findings = append(findings,
		checkReadableFile("signer TLS certificate", cfg.TLSCertFile, false, true),
		checkReadableFile("signer TLS key", cfg.TLSKeyFile, true, true),
		checkReadableFile("signer client CA", cfg.ClientCAFile, false, true),
		checkReadableFile("signer CA certificate", cfg.CACertFile, false, true),
		checkReadableFile("signer CA key", cfg.CAKeyFile, true, strings.TrimSpace(cfg.KeyProvider) == "" || strings.TrimSpace(cfg.KeyProvider) == "file"),
		checkReadableFile("signer CA passphrase", cfg.CAKeyPassphraseFile, true, false),
		checkReadableFile("signer CRL", cfg.CRLFile, false, false),
		checkLogDirectory("signer audit log directory", cfg.AuditLogFile),
	)
	return findings
}

func checkSQLiteDatabaseURL(databaseURL string) doctorFinding {
	if !strings.HasPrefix(strings.TrimSpace(databaseURL), "file:") {
		return doctorFinding{Status: doctorFail, Name: "sqlite database URL", Message: "must start with file:"}
	}
	path := strings.TrimPrefix(strings.TrimSpace(databaseURL), "file:")
	if path == "" {
		return doctorFinding{Status: doctorFail, Name: "sqlite database path", Message: "empty"}
	}
	return checkDirectory("sqlite database directory", filepath.Dir(path), false)
}

func checkPostgresDatabaseURL(databaseURL string) doctorFinding {
	value := strings.TrimSpace(databaseURL)
	if value == "" {
		return doctorFinding{Status: doctorFail, Name: "postgres database URL", Message: "empty"}
	}
	if strings.HasPrefix(value, "postgres://") || strings.HasPrefix(value, "postgresql://") {
		return doctorFinding{Status: doctorOK, Name: "postgres database URL", Message: "configured"}
	}
	return doctorFinding{Status: doctorFail, Name: "postgres database URL", Message: "must start with postgres:// or postgresql://"}
}

func checkReadableFile(name, path string, sensitive, required bool) doctorFinding {
	path = strings.TrimSpace(path)
	if path == "" {
		if required {
			return doctorFinding{Status: doctorFail, Name: name, Message: "not configured"}
		}
		return doctorFinding{Status: doctorWarn, Name: name, Message: "not configured"}
	}
	info, err := os.Stat(path)
	if err != nil {
		if required {
			return doctorFinding{Status: doctorFail, Name: name, Message: fmt.Sprintf("%s: %v", path, err)}
		}
		return doctorFinding{Status: doctorWarn, Name: name, Message: fmt.Sprintf("%s: %v", path, err)}
	}
	if info.IsDir() {
		return doctorFinding{Status: doctorFail, Name: name, Message: path + " is a directory"}
	}
	if sensitive && info.Mode().Perm()&0o077 != 0 {
		return doctorFinding{Status: doctorFail, Name: name + " permissions", Message: fmt.Sprintf("%s mode %04o is too open", path, info.Mode().Perm()), Hint: "use mode 0600 for private key/passphrase files"}
	}
	return doctorFinding{Status: doctorOK, Name: name, Message: path}
}

func checkLogDirectory(name, filePath string) doctorFinding {
	filePath = strings.TrimSpace(filePath)
	if filePath == "" {
		return doctorFinding{Status: doctorWarn, Name: name, Message: "log file not configured"}
	}
	return checkDirectory(name, filepath.Dir(filePath), true)
}

func checkDirectory(name, path string, warnWorldWritable bool) doctorFinding {
	path = strings.TrimSpace(path)
	if path == "" || path == "." {
		return doctorFinding{Status: doctorWarn, Name: name, Message: "directory not configured"}
	}
	info, err := os.Stat(path)
	if err != nil {
		return doctorFinding{Status: doctorFail, Name: name, Message: fmt.Sprintf("%s: %v", path, err)}
	}
	if !info.IsDir() {
		return doctorFinding{Status: doctorFail, Name: name, Message: path + " is not a directory"}
	}
	if warnWorldWritable && info.Mode().Perm()&0o002 != 0 {
		return doctorFinding{Status: doctorWarn, Name: name, Message: fmt.Sprintf("%s is world-writable", path)}
	}
	return doctorFinding{Status: doctorOK, Name: name, Message: path}
}

func writeDoctorFindings(out io.Writer, findings []doctorFinding) {
	fmt.Fprintln(out, "Custodia doctor")
	fmt.Fprintln(out)
	for _, finding := range findings {
		if finding.Message == "" {
			fmt.Fprintf(out, "[%s] %s\n", finding.Status, finding.Name)
		} else {
			fmt.Fprintf(out, "[%s] %s: %s\n", finding.Status, finding.Name, finding.Message)
		}
		if finding.Hint != "" {
			fmt.Fprintf(out, "      Hint: %s\n", finding.Hint)
		}
	}
	fmt.Fprintln(out)
	if doctorHasFailure(findings) {
		fmt.Fprintln(out, "Result: failed")
		return
	}
	if doctorHasWarning(findings) {
		fmt.Fprintln(out, "Result: warning")
		return
	}
	fmt.Fprintln(out, "Result: ok")
}

func doctorHasFailure(findings []doctorFinding) bool {
	for _, finding := range findings {
		if finding.Status == doctorFail {
			return true
		}
	}
	return false
}

func doctorHasWarning(findings []doctorFinding) bool {
	for _, finding := range findings {
		if finding.Status == doctorWarn {
			return true
		}
	}
	return false
}

func loadDoctorSignerConfig(path string) (doctorSignerConfig, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return doctorSignerConfig{}, err
	}
	var raw map[string]any
	if err := yaml.Unmarshal(body, &raw); err != nil {
		return doctorSignerConfig{}, err
	}
	cfg := doctorSignerConfig{}
	cfg.Addr = firstNonEmptyYAMLString(raw, "server.addr", "addr")
	cfg.TLSCertFile = firstNonEmptyYAMLString(raw, "tls.cert_file", "tls_cert_file")
	cfg.TLSKeyFile = firstNonEmptyYAMLString(raw, "tls.key_file", "tls_key_file")
	cfg.ClientCAFile = firstNonEmptyYAMLString(raw, "tls.client_ca_file", "client_ca_file")
	cfg.CACertFile = firstNonEmptyYAMLString(raw, "ca.cert_file", "ca_cert_file")
	cfg.CAKeyFile = firstNonEmptyYAMLString(raw, "ca.key_file", "ca_key_file")
	cfg.CAKeyPassphraseFile = firstNonEmptyYAMLString(raw, "ca.key_passphrase_file", "ca_key_passphrase_file")
	cfg.KeyProvider = firstNonEmptyYAMLString(raw, "ca.key_provider", "key_provider")
	cfg.PKCS11SignCommand = firstNonEmptyYAMLString(raw, "ca.pkcs11_sign_command", "pkcs11_sign_command")
	cfg.CRLFile = firstNonEmptyYAMLString(raw, "revocation.crl_file", "crl_file")
	cfg.AuditLogFile = firstNonEmptyYAMLString(raw, "audit.log_file", "audit_log_file")
	cfg.AdminSubjects = yamlStringList(raw, "admin.subjects", "admin_subjects")
	return cfg, nil
}

func firstNonEmptyYAMLString(raw map[string]any, paths ...string) string {
	for _, path := range paths {
		if value := strings.TrimSpace(yamlScalarString(raw, path)); value != "" {
			return value
		}
	}
	return ""
}

func yamlScalarString(raw map[string]any, path string) string {
	value, ok := yamlLookup(raw, path)
	if !ok || value == nil {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return typed
	case int:
		return fmt.Sprintf("%d", typed)
	case bool:
		return fmt.Sprintf("%t", typed)
	default:
		return fmt.Sprintf("%v", typed)
	}
}

func yamlStringList(raw map[string]any, paths ...string) []string {
	for _, path := range paths {
		value, ok := yamlLookup(raw, path)
		if !ok || value == nil {
			continue
		}
		switch typed := value.(type) {
		case []any:
			items := []string{}
			for _, item := range typed {
				text := strings.TrimSpace(fmt.Sprintf("%v", item))
				if text != "" {
					items = append(items, text)
				}
			}
			return items
		case string:
			items := []string{}
			for _, item := range strings.Split(typed, ",") {
				text := strings.TrimSpace(item)
				if text != "" {
					items = append(items, text)
				}
			}
			return items
		}
	}
	return nil
}

func yamlLookup(raw map[string]any, path string) (any, bool) {
	current := any(raw)
	for _, part := range strings.Split(path, ".") {
		mapping, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = mapping[part]
		if !ok {
			return nil, false
		}
	}
	return current, true
}
