// Copyright (c) 2026 Marco Fortina
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Custodia.
// Custodia is distributed under the GNU Affero General Public License v3.0.
// See the accompanying LICENSE file for details.

package ratelimit

import (
	"context"
	"sync"
	"time"
)

type MemoryLimiter struct {
	mu       sync.Mutex
	counters map[string]memoryCounter
}

type memoryCounter struct {
	window int64
	count  int
}

func NewMemoryLimiter() *MemoryLimiter {
	return &MemoryLimiter{counters: make(map[string]memoryCounter)}
}

func (l *MemoryLimiter) Allow(_ context.Context, key string, limit int) (bool, error) {
	if limit <= 0 {
		return true, nil
	}
	now := time.Now().Unix()
	l.mu.Lock()
	defer l.mu.Unlock()
	counter := l.counters[key]
	if counter.window != now {
		counter = memoryCounter{window: now}
	}
	counter.count++
	l.counters[key] = counter
	return counter.count <= limit, nil
}

func (l *MemoryLimiter) Health(context.Context) error { return nil }
