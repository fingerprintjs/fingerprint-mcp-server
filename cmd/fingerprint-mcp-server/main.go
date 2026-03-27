package main

import (
	"context"
	"crypto/rand"
	"log/slog"
	"os"

	"github.com/fingerprintjs/fingerprint-mcp-server"
	"github.com/fingerprintjs/fingerprint-mcp-server/config"
)

var VERSION string

func main() {
	var logger = slog.Default()
	slog.SetLogLoggerLevel(slog.LevelDebug)

	cfg := config.MustParse()
	if cfg.AuthToken == "" && !cfg.PublicMode {
		// enforce auth token for private mode
		cfg.AuthToken = rand.Text()
	}

	err := fpmcpserver.Run(context.Background(), cfg,
		fpmcpserver.WithLogger(logger),
		fpmcpserver.WithVersion(VERSION),
	)
	if err != nil {
		slog.Error("error while initializing the server", "err", err)
		os.Exit(1)
	}
}
