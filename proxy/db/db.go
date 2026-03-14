package db

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool *pgxpool.Pool
}

func New(dsn string) (*Store, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		return nil, err
	}
	return &Store{pool: pool}, nil
}

func (s *Store) Close() {
	s.pool.Close()
}

func (s *Store) WriteAttackLog(ctx context.Context, clientIP, method, host, path, userAgent, ruleID, category, severity, action, detail, payload string) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO attack_log (client_ip, method, host, path, user_agent, rule_id, category, severity, action, detail, payload)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		clientIP, method, host, path, userAgent, ruleID, category, severity, action, detail, payload,
	)
	return err
}

func (s *Store) WriteRequestStat(ctx context.Context, clientIP, method, path string, statusCode int, durationMs float64, blocked bool) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO request_stats (client_ip, method, path, status_code, duration_ms, blocked)
		 VALUES ($1,$2,$3,$4,$5,$6)`,
		clientIP, method, path, statusCode, durationMs, blocked,
	)
	return err
}

func (s *Store) IsIPBlocklisted(ctx context.Context, ip string) (bool, string, error) {
	var reason string
	err := s.pool.QueryRow(ctx,
		`SELECT reason FROM ip_blocklist WHERE ip = $1 AND (expires_at IS NULL OR expires_at > NOW())`,
		ip,
	).Scan(&reason)
	if err != nil {
		return false, "", nil
	}
	return true, reason, nil
}

func (s *Store) BlockIP(ctx context.Context, ip, reason string) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO ip_blocklist (ip, reason) VALUES ($1, $2) ON CONFLICT (ip) DO UPDATE SET reason = $2, blocked_at = NOW()`,
		ip, reason,
	)
	return err
}
