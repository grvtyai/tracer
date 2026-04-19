// Package apiserver implements the HTTP surface of a Satellite. It hosts the
// endpoints declared in internal/api and delegates all business logic to an
// injected service.Service implementation.
package apiserver

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/grvtyai/startrace/scanner-core/internal/runner/service"
)

type Config struct {
	ListenAddr  string
	AuthToken   string
	SatelliteID string
	Version     string
	Logger      *slog.Logger

	// TLSCertFile and TLSKeyFile enable TLS. Both must be set together.
	// Use GenerateSelfSignedCert to populate them before calling New.
	TLSCertFile string
	TLSKeyFile  string
}

type Server struct {
	cfg     Config
	svc     service.Service
	started time.Time
	httpSrv *http.Server
}

func New(cfg Config, svc service.Service) (*Server, error) {
	if cfg.ListenAddr == "" {
		return nil, fmt.Errorf("apiserver: listen address required")
	}
	if cfg.AuthToken == "" {
		return nil, fmt.Errorf("apiserver: auth token required")
	}
	if svc == nil {
		return nil, fmt.Errorf("apiserver: service required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Server{
		cfg:     cfg,
		svc:     svc,
		started: time.Now().UTC(),
	}, nil
}

// Handler returns the fully configured HTTP handler. Exposed for tests so they
// can wrap it in httptest.NewServer without actually binding a port.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	s.routes(mux)
	return s.middleware(mux)
}

// Start binds the listen address and serves until ctx is cancelled.
func (s *Server) Start(ctx context.Context) error {
	s.httpSrv = &http.Server{
		Addr:              s.cfg.ListenAddr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		// WriteTimeout is intentionally unset: the /runs/{id}/events endpoint
		// is a long-lived SSE stream that must be allowed to write indefinitely.
	}

	errCh := make(chan error, 1)
	go func() {
		s.cfg.Logger.Info("satellite api server listening", "addr", s.cfg.ListenAddr, "tls", s.cfg.TLSCertFile != "")
		var serveErr error
		if s.cfg.TLSCertFile != "" && s.cfg.TLSKeyFile != "" {
			serveErr = s.httpSrv.ListenAndServeTLS(s.cfg.TLSCertFile, s.cfg.TLSKeyFile)
		} else {
			serveErr = s.httpSrv.ListenAndServe()
		}
		if serveErr != nil && serveErr != http.ErrServerClosed {
			errCh <- serveErr
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.httpSrv.Shutdown(shutdownCtx)
	case err := <-errCh:
		return err
	}
}
