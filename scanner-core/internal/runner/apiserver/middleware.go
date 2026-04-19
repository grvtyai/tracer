package apiserver

import (
	"crypto/subtle"
	"net/http"
	"strings"
	"time"

	"github.com/grvtyai/startrace/scanner-core/internal/api"
)

func (s *Server) middleware(next http.Handler) http.Handler {
	return s.recoverMiddleware(s.logMiddleware(s.authMiddleware(next)))
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// /health is unauthenticated so the Nexus can verify reachability
		// before it has (or while revoking) a token.
		if r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}
		authz := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if !strings.HasPrefix(authz, prefix) {
			writeError(w, http.StatusUnauthorized, api.ErrorCodeUnauthorized, "missing bearer token")
			return
		}
		got := authz[len(prefix):]
		if subtle.ConstantTimeCompare([]byte(got), []byte(s.cfg.AuthToken)) != 1 {
			writeError(w, http.StatusUnauthorized, api.ErrorCodeUnauthorized, "invalid token")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r)
		s.cfg.Logger.Info("http",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rw.status,
			"duration_ms", time.Since(start).Milliseconds(),
		)
	})
}

func (s *Server) recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.cfg.Logger.Error("panic in handler", "panic", rec, "path", r.URL.Path)
				writeError(w, http.StatusInternalServerError, api.ErrorCodeInternal, "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// statusRecorder lets the log middleware see the final status code. WriteHeader
// is only called when a handler explicitly sets a non-200 status, so we
// default status to 200.
type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (r *statusRecorder) WriteHeader(code int) {
	if !r.wroteHeader {
		r.status = code
		r.wroteHeader = true
	}
	r.ResponseWriter.WriteHeader(code)
}

// Flush proxies to the underlying ResponseWriter so SSE still flushes through
// this recorder.
func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
