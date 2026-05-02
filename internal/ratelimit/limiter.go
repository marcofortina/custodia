package ratelimit

import "context"

type Limiter interface {
	Allow(ctx context.Context, key string, limit int) (bool, error)
}

type HealthChecker interface {
	Health(ctx context.Context) error
}
