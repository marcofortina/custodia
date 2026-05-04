-- Copyright (c) 2026 Marco Fortina
-- SPDX-License-Identifier: AGPL-3.0-only
--
-- This file is part of Custodia.
-- Custodia is distributed under the GNU Affero General Public License v3.0.
-- See the accompanying LICENSE file for details.

PRAGMA foreign_keys = ON;
-- WAL and busy_timeout make the Lite profile safer for single-node operational use without pretending to provide HA.
PRAGMA journal_mode = WAL;
PRAGMA busy_timeout = 5000;

-- SQLite Lite persistence bootstrap. The Store implementation preserves the same logical model as the FULL store
-- by storing a versioned snapshot of the in-process model in SQLite. This avoids a reduced Lite schema while
-- keeping the Lite profile single-node and dependency-light.
CREATE TABLE IF NOT EXISTS custodia_state (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    payload    TEXT NOT NULL CHECK (length(payload) > 0),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
