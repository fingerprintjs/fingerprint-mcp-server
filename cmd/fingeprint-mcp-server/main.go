package main

import (
	"context"
	"crypto/rand"
	"log/slog"
	"os"

	"github.com/alexflint/go-arg"
	"github.com/fingerprintjs/fingerprint-mcp-server/internal/config"
	"github.com/fingerprintjs/fingerprint-mcp-server/pkg/fpmcpserver"
)

func main() {
	slog.SetLogLoggerLevel(slog.LevelDebug)
	slog.Info("Starting fingerprint-mcp-server", "version", config.VERSION)

	cfg := &config.Config{}
	arg.MustParse(cfg)

	if cfg.AuthToken == "" && !cfg.PublicMode {
		cfg.AuthToken = rand.Text()
	}

	err := fpmcpserver.Run(context.Background(), cfg)
	if err != nil {
		slog.Error("error while initializing the server", "err", err)
		os.Exit(1)
	}
}
