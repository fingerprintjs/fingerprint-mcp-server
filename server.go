package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/fingerprintjs/fingerprint-pro-server-api-go-sdk/v7/sdk"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type App struct {
	server   *mcp.Server
	config   *config
	fpClient *sdk.APIClient
}

func NewApp(config *config) (*App, error) {
	a := &App{
		server: mcp.NewServer(
			&mcp.Implementation{
				Name:    "fingerprint-mcp-server",
				Version: VERSION,
			},
			&mcp.ServerOptions{
				Logger: slog.Default(),
			},
		),
		config: config,
	}

	// Initialize Fingerprint SDK client
	fpSDKConfig := sdk.NewConfiguration()

	// Set region based on configuration
	switch a.config.Region {
	case "eu":
		fpSDKConfig.ChangeRegion(sdk.RegionEU)
	case "asia":
		fpSDKConfig.ChangeRegion(sdk.RegionAsia)
	case "us":
		fpSDKConfig.ChangeRegion(sdk.RegionUS)
	default:
		return nil, fmt.Errorf("unknown region %s, must be one of: us, eu, asia", a.config.Region)
	}

	a.fpClient = sdk.NewAPIClient(fpSDKConfig)

	return a, nil
}

func (a *App) runStdioServer(ctx context.Context) error {
	slog.Debug("starting stdio server")
	if err := a.server.Run(ctx, &mcp.StdioTransport{}); err != nil {
		return fmt.Errorf("running stdio server: %w", err)
	}

	return nil
}

func (a *App) runStreamableHTTPServer(_ context.Context) error {
	handler := mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		return a.server
	}, &mcp.StreamableHTTPOptions{Stateless: false, Logger: slog.Default()})

	mux := http.NewServeMux()
	mux.Handle("/mcp", handler)

	// Health check endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	addr := ":" + strconv.Itoa(a.config.Port)
	slog.Debug("Starting streamable HTTP endpoint", "url", fmt.Sprintf("http://%s/mcp", addr))

	return fmt.Errorf("running streamable http server: %w", http.ListenAndServe(addr, corsMiddleware(mux)))
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Expose-Headers", "Mcp-Session-Id")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Mcp-Session-Id, Mcp-Protocol-Version")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (a *App) registerTools(ctx context.Context) error {
	return errors.Join(
		a.registerGetEventTool(ctx),
		a.registerSearchEventsTool(ctx),
	)
}

func (a *App) registerResources(ctx context.Context) error {

	return errors.Join(
		a.registerEventResource(ctx),
		a.registerEventSchemaResource(ctx),
	)
}

func (a *App) run(ctx context.Context) error {
	var err error
	switch a.config.Transport {
	case "streamable-http":
		err = a.runStreamableHTTPServer(ctx)
	case "stdio":
		err = a.runStdioServer(ctx)
	default:
		err = fmt.Errorf("unsupported transport: %s. Must be one of: stdio, streamable-http", a.config.Transport)
	}

	return err
}
