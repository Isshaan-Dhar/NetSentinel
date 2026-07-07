import chimiddleware "github.com/go-chi/chi/v5/middleware"

func (h *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	clientIP := r.Header.Get("X-Real-IP")
	if clientIP == "" {
		clientIP = strings.Split(r.RemoteAddr, ":")[0]
	}

	// Retrieve unique request identifier for the rate-limiter
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
		go h.db.WriteRequestStat(context.Background(), clientIP, r.Method, r.URL.Path, 403, float64(time.Since(start).Milliseconds()), true)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Forward the tracking request ID down into our sliding window check
	rateLimited, _, err := engine.CheckRateLimit(r.Context(), h.redis, clientIP, reqID)
	if err != nil {
		log.Printf("rate limit error: %v", err)
	}
	if rateLimited {
		metrics.RequestsBlocked.Inc()
		go h.db.WriteAttackLog(context.Background(), clientIP, r.Method, r.Host, r.URL.Path,
			r.Header.Get("User-Agent"), "RATELIMIT-001", "RateLimit", "HIGH", h.wafMode,
			"rate limit exceeded", "")
		go h.db.WriteRequestStat(context.Background(), clientIP, r.Method, r.URL.Path, 429, float64(time.Since(start).Milliseconds()), true)
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

	// Wrap response interceptor to discover exact status returned by backend upstream
	sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
	h.proxy.ServeHTTP(sw, r)

	// Record legitimate metrics to database hypertable
	go h.db.WriteRequestStat(context.Background(), clientIP, r.Method, r.URL.Path, sw.status, float64(time.Since(start).Milliseconds()), false)
}
