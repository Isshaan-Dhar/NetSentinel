package handlers

import (
	"bytes"
	"context"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/isshaan-dhar/NetSentinel/db"
	"github.com/isshaan-dhar/NetSentinel/engine"
	"github.com/isshaan-dhar/NetSentinel/metrics"
	redisstore "github.com/isshaan-dhar/NetSentinel/redis"
)

type ProxyHandler struct {
	proxy   *httputil.ReverseProxy
	db      *db.Store
	redis   *redisstore.Store
	wafMode string
}

func NewProxyHandler(upstream string, store *db.Store, redis *redisstore.Store, wafMode string) (*ProxyHandler, error) {
	target, err := url.Parse(upstream)
	if err != nil {
		return nil, err
	}
	rp := httputil.NewSingleHostReverseProxy(target)
	rp.ModifyResponse = func(resp *http.Response) error {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

		result := engine.InspectResponse(bodyBytes)
		if result.Blocked {
			clientIP := resp.Request.Header.Get("X-Real-IP")
			if clientIP == "" {
				clientIP = strings.Split(resp.Request.RemoteAddr, ":")[0]
			}
			metrics.AttacksDetected.WithLabelValues(result.Rule.Category, result.Rule.Severity, result.Rule.ID).Inc()
			go store.WriteAttackLog(context.Background(), clientIP,
				resp.Request.Method, resp.Request.Host, resp.Request.URL.Path,
				resp.Request.Header.Get("User-Agent"),
				result.Rule.ID, result.Rule.Category, result.Rule.Severity,
				"monitor", "response inspection match", result.Payload)
		}
		return nil
	}
	return &ProxyHandler{proxy: rp, db: store, redis: redis, wafMode: wafMode}, nil
}

func (h *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	clientIP := r.Header.Get("X-Real-IP")
	if clientIP == "" {
		clientIP = strings.Split(r.RemoteAddr, ":")[0]
	}

	metrics.RequestsTotal.Inc()

	blocked, reason, err := h.db.IsIPBlocklisted(r.Context(), clientIP)
	if err != nil {
		log.Printf("blocklist check error: %v", err)
	}
	if blocked {
		metrics.RequestsBlocked.Inc()
		go h.db.WriteRequestStat(context.Background(), clientIP, r.Method, r.URL.Path, 403, float64(time.Since(start).Milliseconds()), true)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	rateLimited, count, err := engine.CheckRateLimit(r.Context(), h.redis, clientIP)
	if err != nil {
		log.Printf("rate limit error: %v", err)
	}
	if rateLimited {
		metrics.RequestsBlocked.Inc()
		go h.db.WriteAttackLog(context.Background(), clientIP, r.Method, r.Host, r.URL.Path,
			r.Header.Get("User-Agent"), "RATELIMIT-001", "RateLimit", "HIGH", h.wafMode,
			"rate limit exceeded", "")
		go h.db.WriteRequestStat(context.Background(), clientIP, r.Method, r.URL.Path, 429, float64(time.Since(start).Milliseconds()), true)
		_ = count
		_ = reason
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		return
	}

	result := engine.InspectRequest(r)
	if result.Blocked {
		metrics.AttacksDetected.WithLabelValues(result.Rule.Category, result.Rule.Severity, result.Rule.ID).Inc()
		go h.db.WriteAttackLog(context.Background(), clientIP, r.Method, r.Host, r.URL.Path,
			r.Header.Get("User-Agent"), result.Rule.ID, result.Rule.Category, result.Rule.Severity,
			h.wafMode, "request inspection match", result.Payload)

		if h.wafMode == "block" {
			metrics.RequestsBlocked.Inc()
			go h.db.WriteRequestStat(context.Background(), clientIP, r.Method, r.URL.Path, 403, float64(time.Since(start).Milliseconds()), true)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
	}

	h.proxy.ServeHTTP(w, r)
	go h.db.WriteRequestStat(context.Background(), clientIP, r.Method, r.URL.Path, 200, float64(time.Since(start).Milliseconds()), false)
}
