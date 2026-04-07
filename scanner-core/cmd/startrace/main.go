package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/grvtyai/tracer/scanner-core/internal/shared/platform"
	"github.com/grvtyai/tracer/scanner-core/internal/shared/storage"
	"github.com/grvtyai/tracer/scanner-core/internal/suite"
)

func main() {
	var (
		listenAddr string
		dataDir    string
		dbPath     string
	)

	flag.StringVar(&listenAddr, "listen", "127.0.0.1:8080", "HTTP listen address")
	flag.StringVar(&dataDir, "data-dir", "", "directory for startrace/tracer persistent data")
	flag.StringVar(&dbPath, "db-path", "", "path to the SQLite database file")
	flag.Parse()

	if err := platform.RequireRootOnLinux("startrace"); err != nil {
		fail(err)
	}

	resolvedDBPath := storage.ResolveDBPath(dataDir, dbPath)
	resolvedDataDir := dataDir
	if resolvedDataDir == "" {
		resolvedDataDir = filepath.Dir(resolvedDBPath)
	}

	repository, err := storage.OpenSQLite(resolvedDBPath)
	if err != nil {
		fail(err)
	}
	defer repository.Close()

	server, err := suite.NewServer(repository, suite.Options{
		DBPath:   resolvedDBPath,
		DataDir:  resolvedDataDir,
		AppName:  "Startrace",
		BasePath: "",
	})
	if err != nil {
		fail(err)
	}

	fmt.Printf("startrace web listening on http://%s\n", listenAddr)
	if err := http.ListenAndServe(listenAddr, server.Handler()); err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "startrace: %v\n", err)
	os.Exit(1)
}
