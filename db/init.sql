CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;

CREATE TABLE IF NOT EXISTS attack_log (
    id          BIGSERIAL,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    client_ip   TEXT NOT NULL,
    method      TEXT NOT NULL,
    host        TEXT NOT NULL,
    path        TEXT NOT NULL,
    user_agent  TEXT,
    rule_id     TEXT NOT NULL,
    category    TEXT NOT NULL,
    severity    TEXT NOT NULL,
    action      TEXT NOT NULL,
    detail      TEXT,
    payload     TEXT
);

SELECT create_hypertable('attack_log', 'occurred_at', if_not_exists => TRUE);

CREATE INDEX IF NOT EXISTS idx_attack_log_client_ip ON attack_log (client_ip, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_attack_log_category  ON attack_log (category,  occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_attack_log_severity  ON attack_log (severity,  occurred_at DESC);

CREATE TABLE IF NOT EXISTS ip_blocklist (
    ip         TEXT PRIMARY KEY,
    reason     TEXT        NOT NULL,
    blocked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS request_stats (
    id          BIGSERIAL,
    occurred_at TIMESTAMPTZ      NOT NULL DEFAULT NOW(),
    client_ip   TEXT             NOT NULL,
    method      TEXT             NOT NULL,
    path        TEXT             NOT NULL,
    status_code INTEGER          NOT NULL,
    duration_ms DOUBLE PRECISION NOT NULL,
    blocked     BOOLEAN          NOT NULL DEFAULT FALSE
);

SELECT create_hypertable('request_stats', 'occurred_at', if_not_exists => TRUE);

CREATE INDEX IF NOT EXISTS idx_request_stats_client_ip ON request_stats (client_ip, occurred_at DESC);