package api

import "time"

// Health is the response body for GET /health.
type Health struct {
	Status      string    `json:"status"`
	Version     string    `json:"version"`
	APIVersion  string    `json:"api_version"`
	SatelliteID string    `json:"satellite_id"`
	StartedAt   time.Time `json:"started_at"`
}

const (
	HealthStatusOK       = "ok"
	HealthStatusDegraded = "degraded"
	HealthStatusError    = "error"
)
