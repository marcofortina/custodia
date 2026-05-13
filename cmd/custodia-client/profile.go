// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"custodia/internal/model"
)

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
