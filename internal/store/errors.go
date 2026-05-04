// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package store

import "errors"

var ErrNotFound = errors.New("not found")
var ErrForbidden = errors.New("forbidden")
var ErrConflict = errors.New("conflict")
var ErrInvalidInput = errors.New("invalid input")
