// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package build

import "testing"

func TestCurrentBuildInfoUsesDefaults(t *testing.T) {
	info := Current()
	if info.Version == "" || info.Commit == "" || info.Date == "" {
		t.Fatalf("expected non-empty build info: %+v", info)
	}
}
