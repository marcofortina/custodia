// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package auditshipper

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"custodia/internal/auditarchive"
	"custodia/internal/auditartifact"
)

type ShipmentManifest struct {
	ShippedAt       time.Time                  `json:"shipped_at"`
	SourceDirectory string                     `json:"source_directory"`
	SinkDirectory   string                     `json:"sink_directory"`
	Files           map[string]string          `json:"files"`
	Verification    auditartifact.Verification `json:"verification"`
}

type ShipmentResult struct {
	SourceDirectory string            `json:"source_directory"`
	SinkDirectory   string            `json:"sink_directory"`
	ManifestPath    string            `json:"manifest_path"`
	Files           map[string]string `json:"files"`
}

func ShipArchive(sourceDir string, sinkRoot string, now time.Time) (ShipmentResult, error) {
	sourceDir = strings.TrimSpace(sourceDir)
	sinkRoot = strings.TrimSpace(sinkRoot)
	if sourceDir == "" {
		return ShipmentResult{}, fmt.Errorf("source archive directory is required")
	}
	if sinkRoot == "" {
		return ShipmentResult{}, fmt.Errorf("sink directory is required")
	}
	manifest, err := readArchiveManifest(sourceDir)
	if err != nil {
		return ShipmentResult{}, err
	}
	exportPath := filepath.Join(sourceDir, manifest.ExportFile)
	sha256Path := filepath.Join(sourceDir, manifest.SHA256File)
	eventsPath := filepath.Join(sourceDir, manifest.EventsFile)
	body, err := os.ReadFile(exportPath)
	if err != nil {
		return ShipmentResult{}, err
	}
	digest, err := os.ReadFile(sha256Path)
	if err != nil {
		return ShipmentResult{}, err
	}
	events, err := os.ReadFile(eventsPath)
	if err != nil {
		return ShipmentResult{}, err
	}
	verification, err := auditartifact.Verify(body, string(digest), string(events))
	if err != nil {
		return ShipmentResult{}, err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	dest := filepath.Join(sinkRoot, filepath.Base(sourceDir))
	if err := os.MkdirAll(dest, 0o750); err != nil {
		return ShipmentResult{}, err
	}
	files := map[string]string{}
	for _, name := range []string{manifest.ExportFile, manifest.SHA256File, manifest.EventsFile, "manifest.json"} {
		copied, err := copyFile(filepath.Join(sourceDir, name), filepath.Join(dest, name), 0o440)
		if err != nil {
			return ShipmentResult{}, err
		}
		files[name] = copied
	}
	shipmentManifest := ShipmentManifest{ShippedAt: now.UTC(), SourceDirectory: sourceDir, SinkDirectory: dest, Files: files, Verification: verification}
	manifestBytes, err := json.MarshalIndent(shipmentManifest, "", "  ")
	if err != nil {
		return ShipmentResult{}, err
	}
	manifestBytes = append(manifestBytes, '\n')
	shipmentManifestPath := filepath.Join(dest, "shipment.json")
	if err := os.WriteFile(shipmentManifestPath, manifestBytes, 0o440); err != nil {
		return ShipmentResult{}, err
	}
	files["shipment.json"] = sha256Hex(manifestBytes)
	return ShipmentResult{SourceDirectory: sourceDir, SinkDirectory: dest, ManifestPath: shipmentManifestPath, Files: files}, nil
}

func readArchiveManifest(dir string) (auditarchive.Manifest, error) {
	data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return auditarchive.Manifest{}, err
	}
	var manifest auditarchive.Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return auditarchive.Manifest{}, err
	}
	if manifest.ExportFile == "" || manifest.SHA256File == "" || manifest.EventsFile == "" {
		return auditarchive.Manifest{}, fmt.Errorf("archive manifest is incomplete")
	}
	return manifest, nil
}

func copyFile(source, dest string, perm os.FileMode) (string, error) {
	input, err := os.Open(source)
	if err != nil {
		return "", err
	}
	defer input.Close()
	output, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return "", err
	}
	defer output.Close()
	hasher := sha256.New()
	if _, err := io.Copy(io.MultiWriter(output, hasher), input); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func sha256Hex(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}
