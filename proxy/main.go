package main

import (
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/isshaan-dhar/NetSentinel/config"
	"github.com/isshaan-dhar/NetSentinel/db"
	"github.com/isshaan-dhar/NetSentinel/handlers"
	"github.com/isshaan-dhar/NetSentinel/metrics"
	redisstore "github.com/isshaan-dhar/NetSentinel/redis"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	cfg := config.Load()

	store, err := db.New(cfg.PostgresDSN)
	if err != nil {
		log.Fatalf("failed to connect to timescaledb: %v", err)
	}
	defer store.Close()

	redis, err := redisstore.New(cfg.RedisAddr)
	if err != nil {
		log.Fatalf("failed to connect to redis: %v", err)
	}
	defer redis.Close()

	proxyHandler, err := handlers.NewProxyHandler(cfg.UpstreamURL, store, redis, cfg.WAFMode)
	if err != nil {
		log.Fatalf("failed to create proxy handler: %v", err)
	}

	internalHandler := handlers.NewInternalHandler(store, cfg.InternalSecret)

	r := chi.NewRouter()
	r.Use(chimiddleware.RequestID)
	r.Use(chimiddleware.RealIP)
	r.Use(chimiddleware.Logger)
	r.Use(chimiddleware.Recoverer)
	r.Use(chimiddleware.Timeout(30 * time.Second))
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			start := time.Now()
			ww := chimiddleware.NewWrapResponseWriter(w, req.ProtoMajor)
			next.ServeHTTP(ww, req)

			routeLabel := "root"
			if req.URL.Path != "/" {
				parts := strings.Split(req.URL.Path, "/")
				if len(parts) > 1 && parts[1] != "" {
					routeLabel = "/" + parts[1]
				}
			}

			metrics.RequestDuration.With(prometheus.Labels{
				"method": req.Method,
				"route":  routeLabel,
				"status": strconv.Itoa(ww.Status()),
			}).Observe(time.Since(start).Seconds())
		})
	})

	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	})
	r.Handle("/metrics", promhttp.Handler())
	r.Post("/internal/anomaly", internalHandler.RecordAnomaly)
	r.Mount("/", proxyHandler)

	srv := &http.Server{
		Addr:              ":" + cfg.AppPort,
		Handler:           r,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	log.Printf("NetSentinel proxy starting on :%s in %s mode", cfg.AppPort, cfg.WAFMode)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
