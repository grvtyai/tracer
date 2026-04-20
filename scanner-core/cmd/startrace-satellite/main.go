// Command startrace-satellite runs a Satellite daemon that exposes the
// Nexus-facing HTTP API backed by the real Radar scan engine.
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/google/uuid"
	"github.com/grvtyai/startrace/scanner-core/internal/runner/apiserver"
	"github.com/grvtyai/startrace/scanner-core/internal/runner/service/radar"
	"github.com/grvtyai/startrace/scanner-core/internal/shared/platform"
)

const version = "0.1.0-dev"

func main() {
	listenAddr := flag.String("listen", "0.0.0.0:8765", "address to listen on")
	satelliteID := flag.String("id", "", "satellite id (auto-generated if empty)")
	tokenEnv := flag.String("token-env", "STARTRACE_SATELLITE_TOKEN", "env var holding the auth token")
	tlsCert := flag.String("tls-cert", "satellite.crt", "TLS certificate file (auto-generated if absent)")
	tlsKey := flag.String("tls-key", "satellite.key", "TLS private key file (auto-generated if absent)")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	if err := platform.RequireRootOnLinux("startrace-satellite"); err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}

	token := os.Getenv(*tokenEnv)
	if token == "" {
		logger.Error("auth token not set", "env", *tokenEnv)
		os.Exit(1)
	}

	if err := apiserver.GenerateSelfSignedCert(*tlsCert, *tlsKey); err != nil {
		logger.Error("generate TLS certificate", "error", err)
		os.Exit(1)
	}

	id := *satelliteID
	if id == "" {
		id = uuid.NewString()
	}

	svc := radar.New(radar.Config{
		SatelliteID: id,
		Version:     version,
		Logger:      logger,
	})
	srv, err := apiserver.New(apiserver.Config{
		ListenAddr:  *listenAddr,
		AuthToken:   token,
		SatelliteID: id,
		Version:     version,
		Logger:      logger,
		TLSCertFile: *tlsCert,
		TLSKeyFile:  *tlsKey,
	}, svc)
	if err != nil {
		logger.Error("create server", "error", err)
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	logger.Info("startrace-satellite starting", "id", id, "version", version)
	if err := srv.Start(ctx); err != nil {
		logger.Error("server stopped", "error", err)
		os.Exit(1)
	}
	logger.Info("startrace-satellite shut down cleanly")
}
