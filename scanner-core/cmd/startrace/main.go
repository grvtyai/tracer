package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/grvtyai/tracer/scanner-core/internal/storage"
	"github.com/grvtyai/tracer/scanner-core/internal/web"
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

	server, err := web.NewServer(repository, web.Options{
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
