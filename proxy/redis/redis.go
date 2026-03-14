package redis

import (
	"context"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

type Store struct {
	client *redis.Client
}

func New(addr string) (*Store, error) {
	client := redis.NewClient(&redis.Options{Addr: addr})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, err
	}
	return &Store{client: client}, nil
}

func (s *Store) Close() error {
	return s.client.Close()
}

func (s *Store) SlidingWindowCount(ctx context.Context, key string, windowSeconds int, maxRequests int64) (int64, error) {
	now := time.Now().UnixMilli()
	windowStart := now - int64(windowSeconds)*1000

	pipe := s.client.Pipeline()
	pipe.ZRemRangeByScore(ctx, key, "0", strconv.FormatInt(windowStart, 10))
	pipe.ZAdd(ctx, key, redis.Z{Score: float64(now), Member: now})
	pipe.ZCard(ctx, key)
	pipe.Expire(ctx, key, time.Duration(windowSeconds)*time.Second)

	results, err := pipe.Exec(ctx)
	if err != nil {
		return 0, err
	}
	count := results[2].(*redis.IntCmd).Val()
	return count, nil
}
