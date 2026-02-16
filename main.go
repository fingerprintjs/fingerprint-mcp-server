//go:generate go run ./cmd/generate-schema

package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/alexflint/go-arg"
)

func main() {
	slog.SetLogLoggerLevel(slog.LevelDebug)

	cfg := &config{}
	arg.MustParse(cfg)
	app, err := NewApp(cfg)
	if err != nil {
		slog.Error("error while initializing the app", "err", err)
		os.Exit(1)
	}

	ctx := context.Background()
	if err := app.registerTools(ctx); err != nil {
		slog.Error("error while registering mcp tools", "err", err)
		os.Exit(1)
	}

	if err := app.registerResources(ctx); err != nil {
		slog.Error("error while registering mcp resources", "err", err)
		os.Exit(1)
	}

	if err := app.run(ctx); err != nil {
		slog.Error("error running the app:", "err", err)
		os.Exit(1)
	}
}
