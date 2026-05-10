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
