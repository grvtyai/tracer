package apiserver

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/grvtyai/startrace/scanner-core/internal/api"
	"github.com/grvtyai/startrace/scanner-core/internal/runner/service"
)

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(api.ErrorResponse{
		Code:    code,
		Message: msg,
	})
}

// writeErr maps a service-layer error to the right HTTP status and response
// body. Internal (5xx) errors are logged and the detail is hidden from the
// client; known (4xx) sentinels leak their wrapped message, which is
// considered safe.
func (s *Server) writeErr(w http.ResponseWriter, err error) {
	status, code := statusForError(err)
	if status >= 500 {
		s.cfg.Logger.Error("handler error", "error", err)
		writeError(w, status, code, "internal error")
		return
	}
	writeError(w, status, code, err.Error())
}

func statusForError(err error) (int, string) {
	switch {
	case errors.Is(err, service.ErrNotFound):
		return http.StatusNotFound, api.ErrorCodeNotFound
	case errors.Is(err, service.ErrBadRequest):
		return http.StatusBadRequest, api.ErrorCodeBadRequest
	case errors.Is(err, service.ErrUnavailable):
		return http.StatusServiceUnavailable, api.ErrorCodeUnavailable
	case errors.Is(err, service.ErrConflict):
		return http.StatusConflict, api.ErrorCodeConflict
	case errors.Is(err, service.ErrPluginMissing):
		return http.StatusBadRequest, api.ErrorCodePluginMissing
	default:
		return http.StatusInternalServerError, api.ErrorCodeInternal
	}
}
