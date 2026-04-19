package apiserver

import (
	"encoding/json"
	"net/http"

	"github.com/grvtyai/startrace/scanner-core/internal/api"
)

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, api.Health{
		Status:      api.HealthStatusOK,
		Version:     s.cfg.Version,
		APIVersion:  api.Version,
		SatelliteID: s.cfg.SatelliteID,
		StartedAt:   s.started,
	})
}

func (s *Server) handleCapabilities(w http.ResponseWriter, r *http.Request) {
	caps, err := s.svc.Capabilities(r.Context())
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, caps)
}

func (s *Server) handleStartRun(w http.ResponseWriter, r *http.Request) {
	var req api.StartRunRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, api.ErrorCodeBadRequest, "invalid json body")
		return
	}
	resp, err := s.svc.StartRun(r.Context(), req)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, resp)
}

func (s *Server) handleListRuns(w http.ResponseWriter, r *http.Request) {
	list, err := s.svc.ListRuns(r.Context())
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleRunStatus(w http.ResponseWriter, r *http.Request) {
	status, err := s.svc.RunStatus(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (s *Server) handleRunEvidence(w http.ResponseWriter, r *http.Request) {
	resp, err := s.svc.RunEvidence(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleRunJobs(w http.ResponseWriter, r *http.Request) {
	resp, err := s.svc.RunJobs(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleCancelRun(w http.ResponseWriter, r *http.Request) {
	if err := s.svc.CancelRun(r.Context(), r.PathValue("id")); err != nil {
		s.writeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRunEvents(w http.ResponseWriter, r *http.Request) {
	ch, err := s.svc.SubscribeEvents(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeErr(w, err)
		return
	}
	streamSSE(w, r, ch)
}
