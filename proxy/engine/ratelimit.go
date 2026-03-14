package engine

import (
	"context"

	redisstore "github.com/isshaan-dhar/NetSentinel/redis"
)

const (
	RateLimitWindow = 60
	RateLimitMax    = 100
)

func CheckRateLimit(ctx context.Context, redis *redisstore.Store, clientIP string) (bool, int64, error) {
	key := "ratelimit:" + clientIP
	count, err := redis.SlidingWindowCount(ctx, key, RateLimitWindow, RateLimitMax)
	if err != nil {
		return false, 0, err
	}
	return count > RateLimitMax, count, nil
}
