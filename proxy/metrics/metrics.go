package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	RequestsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "netsentinel_requests_total",
		Help: "Total number of requests processed",
	})

	RequestsBlocked = promauto.NewCounter(prometheus.CounterOpts{
		Name: "netsentinel_requests_blocked_total",
		Help: "Total number of requests blocked by the WAF",
	})

	AttacksDetected = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "netsentinel_attacks_total",
		Help: "Total number of attacks detected",
	}, []string{"category", "severity", "rule_id"})

	IPsBlocked = promauto.NewCounter(prometheus.CounterOpts{
		Name: "netsentinel_ips_blocked_total",
		Help: "Total number of IPs blocked",
	})

	AnomaliesDetected = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "netsentinel_anomalies_detected_total",
		Help: "Total number of behavioral anomalies detected by sidecar",
	}, []string{"anomaly_type", "severity"})

	RequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "netsentinel_request_duration_seconds",
		Help:    "HTTP request duration in seconds",
		Buckets: prometheus.DefBuckets,
	}, []string{"method", "route", "status"})
)
