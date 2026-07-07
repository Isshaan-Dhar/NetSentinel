package handlers

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/isshaan-dhar/NetSentinel/db"
	"github.com/isshaan-dhar/NetSentinel/metrics"
)

type InternalHandler struct {
	db *db.Store
}

func NewInternalHandler(store *db.Store) *InternalHandler {
	return &InternalHandler{db: store}
}

type anomalyNotification struct {
	AnomalyType string `json:"anomaly_type"`
	Severity    string `json:"severity"`
	ClientIP    string `json:"client_ip"` // Added to receive IP from sidecar
}

func (h *InternalHandler) RecordAnomaly(w http.ResponseWriter, r *http.Request) {
	var n anomalyNotification
	if err := json.NewDecoder(r.Body).Decode(&n); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	metrics.AnomaliesDetected.WithLabelValues(n.AnomalyType, n.Severity).Inc()

	// ARCHITECTURAL FIX: Enforce the block directly to the database.
	if n.ClientIP != "" {
		go func(ip, anomalyType string) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err := h.db.BlockIP(ctx, ip, "Behavioral Anomaly: "+anomalyType)
			if err != nil {
				log.Printf("failed to block IP %s: %v", ip, err)
			} else {
				log.Printf("Successfully blocked IP %s due to %s", ip, anomalyType)
			}
		}(n.ClientIP, n.AnomalyType)
	}

	w.WriteHeader(http.StatusNoContent)
}
