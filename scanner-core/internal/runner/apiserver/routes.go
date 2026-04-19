package apiserver

import "net/http"

func (s *Server) routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("GET /capabilities", s.handleCapabilities)
	mux.HandleFunc("POST /runs", s.handleStartRun)
	mux.HandleFunc("GET /runs", s.handleListRuns)
	mux.HandleFunc("GET /runs/{id}/status", s.handleRunStatus)
	mux.HandleFunc("GET /runs/{id}/events", s.handleRunEvents)
	mux.HandleFunc("GET /runs/{id}/evidence", s.handleRunEvidence)
	mux.HandleFunc("GET /runs/{id}/jobs", s.handleRunJobs)
	mux.HandleFunc("DELETE /runs/{id}", s.handleCancelRun)
}
