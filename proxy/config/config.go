package config

import (
	"os"
)

type Config struct {
	AppPort        string
	PostgresDSN    string
	RedisAddr      string
	AESKey         string
	WAFMode        string
	UpstreamURL    string
	InternalSecret string
}

func Load() *Config {
	return &Config{
		AppPort:        getEnv("APP_PORT", "8080"),
		PostgresDSN:    "postgres://" + getEnv("POSTGRES_USER", "netsentinel") + ":" + getEnv("POSTGRES_PASSWORD", "changeme") + "@" + getEnv("POSTGRES_HOST", "timescaledb") + ":" + getEnv("POSTGRES_PORT", "5432") + "/" + getEnv("POSTGRES_DB", "netsentinel") + "?sslmode=disable",
		RedisAddr:      getEnv("REDIS_ADDR", "redis:6379"),
		WAFMode:        getEnv("WAF_MODE", "block"),
		UpstreamURL:    getEnv("UPSTREAM_URL", "http://test-backend:9000"),
		InternalSecret: getEnv("INTERNAL_API_SECRET", "default-secret"), // SECURITY FIX: Add configurable internal secret
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
