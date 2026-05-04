// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package ratelimit

import "context"

type Limiter interface {
	Allow(ctx context.Context, key string, limit int) (bool, error)
}

type HealthChecker interface {
	Health(ctx context.Context) error
}
