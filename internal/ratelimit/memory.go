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
