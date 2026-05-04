// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package auditarchive

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"custodia/internal/auditartifact"
)

type Manifest struct {
	ArchivedAt   time.Time                  `json:"archived_at"`
	ExportFile   string                     `json:"export_file"`
	SHA256File   string                     `json:"sha256_file"`
	EventsFile   string                     `json:"events_file"`
	Verification auditartifact.Verification `json:"verification"`
}

type ArchiveResult struct {
	Directory    string                     `json:"directory"`
	ExportPath   string                     `json:"export_path"`
	SHA256Path   string                     `json:"sha256_path"`
	EventsPath   string                     `json:"events_path"`
	ManifestPath string                     `json:"manifest_path"`
	Verification auditartifact.Verification `json:"verification"`
}

// Archive verifies the export before writing any archive files. The archive is an
// evidence bundle, not merely a copy of API output.
func Archive(exportBody []byte, sha256Value string, eventsValue string, archiveDir string, now time.Time) (ArchiveResult, error) {
	archiveDir = strings.TrimSpace(archiveDir)
	if archiveDir == "" {
		return ArchiveResult{}, fmt.Errorf("archive directory is required")
	}
	verification, err := auditartifact.Verify(exportBody, sha256Value, eventsValue)
	if err != nil {
		return ArchiveResult{}, err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	stamp := now.UTC().Format("20060102T150405Z")
	dir := filepath.Join(archiveDir, stamp)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return ArchiveResult{}, err
	}
	result := ArchiveResult{
		Directory:    dir,
		ExportPath:   filepath.Join(dir, "custodia-audit.jsonl"),
		SHA256Path:   filepath.Join(dir, "custodia-audit.jsonl.sha256"),
		EventsPath:   filepath.Join(dir, "custodia-audit.jsonl.events"),
		ManifestPath: filepath.Join(dir, "manifest.json"),
		Verification: verification,
	}
	if err := os.WriteFile(result.ExportPath, exportBody, 0o640); err != nil {
		return ArchiveResult{}, err
	}
	if err := os.WriteFile(result.SHA256Path, []byte(strings.TrimSpace(sha256Value)+"\n"), 0o640); err != nil {
		return ArchiveResult{}, err
	}
	if err := os.WriteFile(result.EventsPath, []byte(strings.TrimSpace(eventsValue)+"\n"), 0o640); err != nil {
		return ArchiveResult{}, err
	}
	manifest := Manifest{ArchivedAt: now.UTC(), ExportFile: filepath.Base(result.ExportPath), SHA256File: filepath.Base(result.SHA256Path), EventsFile: filepath.Base(result.EventsPath), Verification: verification}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return ArchiveResult{}, err
	}
	manifestBytes = append(manifestBytes, '\n')
	if err := os.WriteFile(result.ManifestPath, manifestBytes, 0o640); err != nil {
		return ArchiveResult{}, err
	}
	return result, nil
}
