package handlers

import (
	"bytes"
	"context"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/isshaan-dhar/NetSentinel/db"
	"github.com/isshaan-dhar/NetSentinel/engine"
	"github.com/isshaan-dhar/NetSentinel/metrics"
	redisstore "github.com/isshaan-dhar/NetSentinel/redis"
)

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

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
		contentType := resp.Header.Get("Content-Type")
		if contentType != "" &&
			!strings.Contains(contentType, "text/") &&
			!strings.Contains(contentType, "application/json") &&
			!strings.Contains(contentType, "application/xml") {
			return nil
		}

		bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
		if err != nil {
			return err
		}

		resp.Body = io.NopCloser(io.MultiReader(bytes.NewReader(bodyBytes), resp.Body))

		result := engine.InspectResponse(bodyBytes)
		if result.Blocked {
			clientIP := resp.Request.Header.Get("X-Real-IP")
			if clientIP == "" {
				clientIP = strings.Split(resp.Request.RemoteAddr, ":")[0]
			}
			metrics.AttacksDetected.WithLabelValues(result.Rule.Category, result.Rule.Severity, result.Rule.ID).Inc()

			go func(ip, method, host, path, ua string, rule *engine.Rule, payload string) {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				store.WriteAttackLog(ctx, ip, method, host, path, ua,
					rule.ID, rule.Category, rule.Severity, wafMode, "response inspection match", payload)
			}(clientIP, resp.Request.Method, resp.Request.Host, resp.Request.URL.Path, resp.Request.Header.Get("User-Agent"), result.Rule, result.Payload)

			if wafMode == "block" {
				blockMsg := "NetSentinel WAF: Response Blocked Due to Sensitive Data Leakage"
				resp.StatusCode = http.StatusForbidden
				resp.Body = io.NopCloser(strings.NewReader(blockMsg))
				resp.Header.Set("Content-Length", strconv.Itoa(len(blockMsg)))
				resp.Header.Set("Content-Type", "text/plain; charset=utf-8")
				resp.Header.Del("Transfer-Encoding")
			}
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

	reqID := chimiddleware.GetReqID(r.Context())
	if reqID == "" {
		reqID = "internal-fallback-id"
	}

	metrics.RequestsTotal.Inc()

	blocked, _, err := h.db.IsIPBlocklisted(r.Context(), clientIP)
	if err != nil {
		log.Printf("blocklist check error: %v", err)
	}
	if blocked {
		metrics.RequestsBlocked.Inc()
		go func(ip, method, path string, dur float64) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			h.db.WriteRequestStat(ctx, ip, method, path, 403, dur, true)
		}(clientIP, r.Method, r.URL.Path, float64(time.Since(start).Milliseconds()))
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	rateLimited, _, err := engine.CheckRateLimit(r.Context(), h.redis, clientIP, reqID)
	if err != nil {
		log.Printf("rate limit error: %v", err)
	}
	if rateLimited {
		metrics.RequestsBlocked.Inc()
		go func(ip, method, host, path, ua string, dur float64) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			h.db.WriteAttackLog(ctx, ip, method, host, path, ua, "RATELIMIT-001", "RateLimit", "HIGH", h.wafMode, "rate limit exceeded", "")
			h.db.WriteRequestStat(ctx, ip, method, path, 429, dur, true)
		}(clientIP, r.Method, r.Host, r.URL.Path, r.Header.Get("User-Agent"), float64(time.Since(start).Milliseconds()))
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		return
	}

	result := engine.InspectRequest(r)
	if result.Blocked {
		metrics.AttacksDetected.WithLabelValues(result.Rule.Category, result.Rule.Severity, result.Rule.ID).Inc()

		go func(ip, method, host, path, ua string, rule *engine.Rule, payload string, dur float64) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			h.db.WriteAttackLog(ctx, ip, method, host, path, ua, rule.ID, rule.Category, rule.Severity, h.wafMode, "request inspection match", payload)
			if h.wafMode == "block" {
				h.db.WriteRequestStat(ctx, ip, method, path, 403, dur, true)
			}
		}(clientIP, r.Method, r.Host, r.URL.Path, r.Header.Get("User-Agent"), result.Rule, result.Payload, float64(time.Since(start).Milliseconds()))

		if h.wafMode == "block" {
			metrics.RequestsBlocked.Inc()
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
	}

	sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
	h.proxy.ServeHTTP(sw, r)

	go func(ip, method, path string, status int, dur float64) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		h.db.WriteRequestStat(ctx, ip, method, path, status, dur, false)
	}(clientIP, r.Method, r.URL.Path, sw.status, float64(time.Since(start).Milliseconds()))
}
