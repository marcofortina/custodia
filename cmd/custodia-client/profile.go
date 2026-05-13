// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"custodia/internal/model"
)

const clientProfileExportFormat = "custodia-client-profile-export-v1"

type clientProfileExport struct {
	Format             string                    `json:"format"`
	ClientID           string                    `json:"client_id"`
	IncludesPrivateKey bool                      `json:"includes_private_keys"`
	Files              []clientProfileExportFile `json:"files"`
}

type clientProfileExportFile struct {
	Name    string `json:"name"`
	Role    string `json:"role"`
	Mode    string `json:"mode"`
	DataB64 string `json:"data_b64"`
}

type clientProfileExportSpec struct {
	path    string
	name    string
	role    string
	mode    os.FileMode
	private bool
}

type clientProfilePaths struct {
	Dir           string
	MTLSKey       string
	MTLSCSR       string
	MTLSCert      string
	CA            string
	CryptoPrivate string
	CryptoPublic  string
	Config        string
	ServerURL     string
}

func defaultClientConfigPath(clientID string) (string, error) {
	paths, err := defaultClientProfilePaths(clientID)
	if err != nil {
		return "", err
	}
	return paths.Config, nil
}

func defaultClientProfilePaths(clientID string) (clientProfilePaths, error) {
	clientID = strings.TrimSpace(clientID)
	if !model.ValidClientID(clientID) {
		return clientProfilePaths{}, fmt.Errorf("invalid client id: %q", clientID)
	}
	configDir, err := os.UserConfigDir()
	if err != nil {
		return clientProfilePaths{}, fmt.Errorf("resolve user config directory: %w", err)
	}
	dir := filepath.Join(configDir, "custodia", clientID)
	return clientProfilePaths{
		Dir:           dir,
		MTLSKey:       filepath.Join(dir, clientID+".key"),
		MTLSCSR:       filepath.Join(dir, clientID+".csr"),
		MTLSCert:      filepath.Join(dir, clientID+".crt"),
		CA:            filepath.Join(dir, "ca.crt"),
		CryptoPrivate: filepath.Join(dir, clientID+".x25519.json"),
		CryptoPublic:  filepath.Join(dir, clientID+".x25519.pub.json"),
		Config:        filepath.Join(dir, clientID+".config.json"),
		ServerURL:     filepath.Join(dir, "server_url"),
	}, nil
}

func readDefaultServerURL(clientID string) (string, error) {
	paths, err := defaultClientProfilePaths(clientID)
	if err != nil {
		return "", err
	}
	payload, err := os.ReadFile(paths.ServerURL)
	if err != nil {
		return "", fmt.Errorf("read server URL from %s: %w", paths.ServerURL, err)
	}
	value := strings.TrimSpace(string(payload))
	if value == "" {
		return "", fmt.Errorf("server URL profile file is empty: %s", paths.ServerURL)
	}
	return value, nil
}

func ensureClientProfileDir(dir string) error {
	if strings.TrimSpace(dir) == "" {
		return fmt.Errorf("client profile directory is required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create client profile directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("set client profile directory permissions: %w", err)
	}
	return nil
}

func defaultTransportConfigFromClientID(transport *transportFlags, clientID string) error {
	if transport == nil {
		return nil
	}
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return nil
	}
	paths, err := defaultClientProfilePaths(clientID)
	if err != nil {
		return err
	}
	if strings.TrimSpace(transport.configFile) == "" {
		transport.configFile = paths.Config
	}
	return nil
}

func copyFileExclusive(src, dst string, mode os.FileMode) error {
	src = strings.TrimSpace(src)
	dst = strings.TrimSpace(dst)
	if src == "" || dst == "" {
		return fmt.Errorf("source and destination paths are required")
	}
	body, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("read %s: %w", src, err)
	}
	return writeExclusive(dst, body, mode)
}

func clientProfilesBaseDir() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve user config directory: %w", err)
	}
	return filepath.Join(configDir, "custodia"), nil
}

func listClientProfileIDs() ([]string, error) {
	baseDir, err := clientProfilesBaseDir()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(baseDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, fmt.Errorf("read client profiles from %s: %w", baseDir, err)
	}
	profiles := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		if model.ValidClientID(name) {
			profiles = append(profiles, name)
		}
	}
	sort.Strings(profiles)
	return profiles, nil
}

type clientProfileSummary struct {
	ClientID            string `json:"client_id"`
	ProfileDir          string `json:"profile_dir"`
	ConfigFile          string `json:"config_file"`
	ServerURLFile       string `json:"server_url_file"`
	MTLSCSRFile         string `json:"mtls_csr_file"`
	MTLSCertFile        string `json:"mtls_cert_file"`
	CAFile              string `json:"ca_file"`
	CryptoPublicKeyFile string `json:"crypto_public_key_file"`
	Exists              bool   `json:"exists"`
	HasConfig           bool   `json:"has_config"`
	HasServerURL        bool   `json:"has_server_url"`
	HasMTLSKey          bool   `json:"has_mtls_key"`
	HasMTLSCSR          bool   `json:"has_mtls_csr"`
	HasMTLSCert         bool   `json:"has_mtls_cert"`
	HasCA               bool   `json:"has_ca"`
	HasCryptoPrivateKey bool   `json:"has_crypto_private_key"`
	HasCryptoPublicKey  bool   `json:"has_crypto_public_key"`
}

func buildClientProfileSummary(clientID string) (clientProfileSummary, error) {
	paths, err := defaultClientProfilePaths(clientID)
	if err != nil {
		return clientProfileSummary{}, err
	}
	return clientProfileSummary{
		ClientID:            strings.TrimSpace(clientID),
		ProfileDir:          paths.Dir,
		ConfigFile:          paths.Config,
		ServerURLFile:       paths.ServerURL,
		MTLSCSRFile:         paths.MTLSCSR,
		MTLSCertFile:        paths.MTLSCert,
		CAFile:              paths.CA,
		CryptoPublicKeyFile: paths.CryptoPublic,
		Exists:              pathExists(paths.Dir),
		HasConfig:           pathExists(paths.Config),
		HasServerURL:        pathExists(paths.ServerURL),
		HasMTLSKey:          pathExists(paths.MTLSKey),
		HasMTLSCSR:          pathExists(paths.MTLSCSR),
		HasMTLSCert:         pathExists(paths.MTLSCert),
		HasCA:               pathExists(paths.CA),
		HasCryptoPrivateKey: pathExists(paths.CryptoPrivate),
		HasCryptoPublicKey:  pathExists(paths.CryptoPublic),
	}, nil
}

func deleteClientProfile(paths clientProfilePaths) error {
	if strings.TrimSpace(paths.Dir) == "" {
		return fmt.Errorf("client profile directory is required")
	}
	info, err := os.Stat(paths.Dir)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("client profile does not exist: %s", paths.Dir)
		}
		return fmt.Errorf("check client profile %s: %w", paths.Dir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("client profile is not a directory: %s", paths.Dir)
	}
	if err := os.RemoveAll(paths.Dir); err != nil {
		return fmt.Errorf("delete client profile %s: %w", paths.Dir, err)
	}
	return nil
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func exportClientProfile(paths clientProfilePaths, includePrivateKeys bool) (clientProfileExport, error) {
	if strings.TrimSpace(paths.Dir) == "" {
		return clientProfileExport{}, fmt.Errorf("client profile directory is required")
	}
	info, err := os.Stat(paths.Dir)
	if err != nil {
		if os.IsNotExist(err) {
			return clientProfileExport{}, fmt.Errorf("client profile does not exist: %s", paths.Dir)
		}
		return clientProfileExport{}, fmt.Errorf("check client profile %s: %w", paths.Dir, err)
	}
	if !info.IsDir() {
		return clientProfileExport{}, fmt.Errorf("client profile is not a directory: %s", paths.Dir)
	}
	clientID := strings.TrimSpace(filepath.Base(paths.Dir))
	export := clientProfileExport{Format: clientProfileExportFormat, ClientID: clientID, IncludesPrivateKey: includePrivateKeys}
	for _, spec := range clientProfileExportSpecs(paths) {
		if spec.private && !includePrivateKeys {
			continue
		}
		body, err := os.ReadFile(spec.path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return clientProfileExport{}, fmt.Errorf("read profile file %s: %w", spec.name, err)
		}
		export.Files = append(export.Files, clientProfileExportFile{
			Name:    spec.name,
			Role:    spec.role,
			Mode:    fmt.Sprintf("%04o", spec.mode.Perm()),
			DataB64: base64.StdEncoding.EncodeToString(body),
		})
	}
	if len(export.Files) == 0 {
		return clientProfileExport{}, fmt.Errorf("client profile has no exportable files: %s", paths.Dir)
	}
	return export, nil
}

func clientProfileExportSpecs(paths clientProfilePaths) []clientProfileExportSpec {
	clientID := strings.TrimSpace(filepath.Base(paths.Dir))
	return []clientProfileExportSpec{
		{path: paths.Config, name: clientID + ".config.json", role: "config", mode: keyFileMode},
		{path: paths.ServerURL, name: "server_url", role: "server_url", mode: publicFileMode},
		{path: paths.MTLSCSR, name: clientID + ".csr", role: "mtls_csr", mode: publicFileMode},
		{path: paths.MTLSCert, name: clientID + ".crt", role: "mtls_cert", mode: publicFileMode},
		{path: paths.CA, name: "ca.crt", role: "ca_cert", mode: publicFileMode},
		{path: paths.CryptoPublic, name: clientID + ".x25519.pub.json", role: "crypto_public_key", mode: publicFileMode},
		{path: paths.MTLSKey, name: clientID + ".key", role: "mtls_private_key", mode: keyFileMode, private: true},
		{path: paths.CryptoPrivate, name: clientID + ".x25519.json", role: "crypto_private_key", mode: keyFileMode, private: true},
	}
}

func importClientProfile(archive clientProfileExport, targetClientID string, force bool) (clientProfilePaths, error) {
	if archive.Format != clientProfileExportFormat {
		return clientProfilePaths{}, fmt.Errorf("unsupported client profile export format: %s", archive.Format)
	}
	archiveClientID := strings.TrimSpace(archive.ClientID)
	if !model.ValidClientID(archiveClientID) {
		return clientProfilePaths{}, fmt.Errorf("invalid exported client id: %q", archive.ClientID)
	}
	targetClientID = strings.TrimSpace(targetClientID)
	if targetClientID != "" && targetClientID != archiveClientID {
		return clientProfilePaths{}, fmt.Errorf("--client-id %q does not match exported client id %q", targetClientID, archiveClientID)
	}
	if targetClientID == "" {
		targetClientID = archiveClientID
	}
	paths, err := defaultClientProfilePaths(targetClientID)
	if err != nil {
		return clientProfilePaths{}, err
	}
	if _, err := os.Stat(paths.Dir); err == nil && !force {
		return clientProfilePaths{}, fmt.Errorf("refusing to overwrite existing client profile: %s; pass --force to replace it", paths.Dir)
	} else if err != nil && !os.IsNotExist(err) {
		return clientProfilePaths{}, fmt.Errorf("check client profile %s: %w", paths.Dir, err)
	}
	baseDir := filepath.Dir(paths.Dir)
	if err := os.MkdirAll(baseDir, 0o700); err != nil {
		return clientProfilePaths{}, fmt.Errorf("create client profile base directory: %w", err)
	}
	tmpDir, err := os.MkdirTemp(baseDir, "."+targetClientID+".import-*")
	if err != nil {
		return clientProfilePaths{}, fmt.Errorf("create temporary import directory: %w", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(tmpDir)
		}
	}()
	if err := os.Chmod(tmpDir, 0o700); err != nil {
		return clientProfilePaths{}, fmt.Errorf("set temporary import directory permissions: %w", err)
	}
	tmpPaths := paths
	tmpPaths.Dir = tmpDir
	tmpPaths.MTLSKey = filepath.Join(tmpDir, targetClientID+".key")
	tmpPaths.MTLSCSR = filepath.Join(tmpDir, targetClientID+".csr")
	tmpPaths.MTLSCert = filepath.Join(tmpDir, targetClientID+".crt")
	tmpPaths.CA = filepath.Join(tmpDir, "ca.crt")
	tmpPaths.CryptoPrivate = filepath.Join(tmpDir, targetClientID+".x25519.json")
	tmpPaths.CryptoPublic = filepath.Join(tmpDir, targetClientID+".x25519.pub.json")
	tmpPaths.Config = filepath.Join(tmpDir, targetClientID+".config.json")
	tmpPaths.ServerURL = filepath.Join(tmpDir, "server_url")
	if len(archive.Files) == 0 {
		return clientProfilePaths{}, fmt.Errorf("client profile export contains no files")
	}
	importedRoles := map[string]bool{}
	for _, file := range archive.Files {
		target, mode, err := importTargetForRole(tmpPaths, file.Role)
		if err != nil {
			return clientProfilePaths{}, err
		}
		body, err := base64.StdEncoding.DecodeString(strings.TrimSpace(file.DataB64))
		if err != nil {
			return clientProfilePaths{}, fmt.Errorf("decode profile export file %s: %w", file.Role, err)
		}
		if err := writeExclusive(target, body, mode); err != nil {
			return clientProfilePaths{}, err
		}
		importedRoles[file.Role] = true
	}
	if importedRoles["config"] {
		config, err := normalizedImportedClientConfig(archive, paths, importedRoles)
		if err != nil {
			return clientProfilePaths{}, err
		}
		if err := os.Remove(tmpPaths.Config); err != nil && !os.IsNotExist(err) {
			return clientProfilePaths{}, fmt.Errorf("replace imported config: %w", err)
		}
		if err := writeJSONFileExclusive(tmpPaths.Config, config, keyFileMode); err != nil {
			return clientProfilePaths{}, err
		}
	}
	if force {
		if err := os.RemoveAll(paths.Dir); err != nil {
			return clientProfilePaths{}, fmt.Errorf("replace existing client profile %s: %w", paths.Dir, err)
		}
	}
	if err := os.Rename(tmpDir, paths.Dir); err != nil {
		return clientProfilePaths{}, fmt.Errorf("install imported client profile: %w", err)
	}
	cleanup = false
	if err := os.Chmod(paths.Dir, 0o700); err != nil {
		return clientProfilePaths{}, fmt.Errorf("set client profile directory permissions: %w", err)
	}
	return paths, nil
}

func importTargetForRole(paths clientProfilePaths, role string) (string, os.FileMode, error) {
	switch strings.TrimSpace(role) {
	case "config":
		return paths.Config, keyFileMode, nil
	case "server_url":
		return paths.ServerURL, publicFileMode, nil
	case "mtls_csr":
		return paths.MTLSCSR, publicFileMode, nil
	case "mtls_cert":
		return paths.MTLSCert, publicFileMode, nil
	case "ca_cert":
		return paths.CA, publicFileMode, nil
	case "crypto_public_key":
		return paths.CryptoPublic, publicFileMode, nil
	case "mtls_private_key":
		return paths.MTLSKey, keyFileMode, nil
	case "crypto_private_key":
		return paths.CryptoPrivate, keyFileMode, nil
	default:
		return "", 0, fmt.Errorf("unsupported profile export file role: %s", role)
	}
}

func normalizedImportedClientConfig(archive clientProfileExport, paths clientProfilePaths, importedRoles map[string]bool) (clientConfigFile, error) {
	config := clientConfigFile{ClientID: archive.ClientID}
	for _, file := range archive.Files {
		if file.Role != "config" {
			continue
		}
		body, err := base64.StdEncoding.DecodeString(strings.TrimSpace(file.DataB64))
		if err != nil {
			return clientConfigFile{}, fmt.Errorf("decode profile export config: %w", err)
		}
		if err := json.Unmarshal(body, &config); err != nil {
			return clientConfigFile{}, fmt.Errorf("parse profile export config: %w", err)
		}
		break
	}
	config.ClientID = archive.ClientID
	if strings.TrimSpace(config.ServerURL) == "" {
		if serverURL, ok, err := exportedServerURL(archive); err != nil {
			return clientConfigFile{}, err
		} else if ok {
			config.ServerURL = serverURL
		}
	}
	if importedRoles["mtls_cert"] {
		config.CertFile = paths.MTLSCert
	}
	if importedRoles["mtls_private_key"] {
		config.KeyFile = paths.MTLSKey
	} else {
		config.KeyFile = ""
	}
	if importedRoles["ca_cert"] {
		config.CAFile = paths.CA
	}
	if importedRoles["crypto_private_key"] {
		config.CryptoKey = paths.CryptoPrivate
	} else {
		config.CryptoKey = ""
	}
	return config, nil
}

func exportedServerURL(archive clientProfileExport) (string, bool, error) {
	for _, file := range archive.Files {
		if file.Role != "server_url" {
			continue
		}
		body, err := base64.StdEncoding.DecodeString(strings.TrimSpace(file.DataB64))
		if err != nil {
			return "", false, fmt.Errorf("decode profile export server_url: %w", err)
		}
		return strings.TrimSpace(string(body)), true, nil
	}
	return "", false, nil
}
