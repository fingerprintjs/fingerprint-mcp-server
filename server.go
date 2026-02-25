package fpmcpserver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/fingerprintjs/fingerprint-mcp-server/config"
	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type App struct {
	server *mcp.Server
	cfg    *config.Config
	opts   *opts
}

type opts struct {
	l *slog.Logger
}

func (o opts) logger() *slog.Logger {
	if o.l != nil {
		return o.l
	}
	return slog.Default()
}

type OptFunc func(o *opts)

func WithLogger(logger *slog.Logger) OptFunc {
	return func(o *opts) {
		o.l = logger
	}
}

func Run(ctx context.Context, config *config.Config, options ...OptFunc) error {
	opts := &opts{}
	for _, f := range options {
		f(opts)
	}
	app, err := New(config, opts)
	if err != nil {
		return err
	}

	if err := app.registerTools(ctx); err != nil {
		return fmt.Errorf("registering tools: %w", err)
	}

	if err := app.registerResources(ctx); err != nil {
		return fmt.Errorf("registering resources: %w", err)
	}

	if err := app.registerPrompts(ctx); err != nil {
		return fmt.Errorf("registering prompts: %w", err)
	}

	return app.run(ctx)
}

func New(cfg *config.Config, opts *opts) (*App, error) {
	if cfg == nil {
		cfg = &config.Config{}
	}
	a := &App{
		server: mcp.NewServer(
			&mcp.Implementation{
				Name:    "fingerprint-mcp-server",
				Version: cfg.Version(),
			},
			&mcp.ServerOptions{
				Logger: slog.Default(),
			},
		),
		cfg:  cfg,
		opts: opts,
	}

	return a, nil
}

func (a *App) runStdioServer(ctx context.Context) error {
	a.opts.logger().Debug("starting stdio server")
	if err := a.server.Run(ctx, &mcp.StdioTransport{}); err != nil {
		return fmt.Errorf("running stdio server: %w", err)
	}

	return nil
}

func (a *App) validateAuthToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if a.cfg.AuthToken != "" && request.Header.Get("Authorization") != fmt.Sprintf("Bearer %s", a.cfg.AuthToken) {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(writer, request)
	})
}

func (a *App) verifyAuthToken(_ context.Context, authToken string, _ *http.Request) (*auth.TokenInfo, error) {
	if a.cfg.AuthToken != authToken {
		return nil, auth.ErrInvalidToken
	}

	return &auth.TokenInfo{
		Expiration: time.Now().Add(24 * time.Hour), // this token never expires
	}, nil
}

func (a *App) runStreamableHTTPServer(_ context.Context) error {
	var handler http.Handler = mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		return a.server
	}, &mcp.StreamableHTTPOptions{Stateless: config.STATELESS, Logger: a.opts.logger()})

	if a.cfg.AuthToken != "" {
		a.opts.logger().Info("pass auth token in `Authorization: Bearer` http header to access this server", "auth_token", a.cfg.AuthToken)
		apiKeyAuth := auth.RequireBearerToken(a.verifyAuthToken, &auth.RequireBearerTokenOptions{})

		handler = apiKeyAuth(handler)
	}

	mux := http.NewServeMux()
	mux.Handle("/mcp", handler)
	// Health check endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	addr := ":" + strconv.Itoa(a.cfg.Port)

	var mode string
	if a.cfg.PublicMode {
		mode = "public"
	} else {
		mode = "private"
	}

	var proto string
	if a.cfg.TLSCert != "" && a.cfg.TLSKey != "" {
		proto = "https"
	} else {
		proto = "http"
	}
	a.opts.logger().Info("starting streamable-http endpoint", "url", fmt.Sprintf("%s://%s/mcp", proto, addr), "mode", mode)

	var err error
	if proto == "https" {
		err = http.ListenAndServeTLS(addr, a.cfg.TLSCert, a.cfg.TLSKey, a.corsMiddleware(mux))
	} else {
		err = http.ListenAndServe(addr, a.corsMiddleware(mux))
	}
	return fmt.Errorf("running streamable-http server: %w", err)
}

func (a *App) corsMiddleware(next http.Handler) http.Handler {
	allowHeaders := []string{
		"Content-Type", "Mcp-Protocol-Version",
		"x-custom-auth-headers", // workaround for mcp inspector that sends this header by mistake. see: https://github.com/modelcontextprotocol/inspector/issues/1100
	}
	if !config.STATELESS {
		allowHeaders = append(allowHeaders, "Mcp-Session-Id")
	}
	if a.cfg.AuthToken != "" {
		allowHeaders = append(allowHeaders, "Authorization")
	}
	if a.cfg.PublicMode {
		allowHeaders = append(allowHeaders,
			headerMgmtApiKey,
			headerServerApiKey,
			headerServerApiRegion,
		)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		if !config.STATELESS {
			w.Header().Set("Access-Control-Expose-Headers", "Mcp-Session-Id")
		}
		w.Header().Set("Access-Control-Allow-Headers", strings.Join(allowHeaders, ", "))

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (a *App) registerTools(ctx context.Context) error {
	var errs []error

	if a.cfg.PublicMode || (!a.cfg.PublicMode && a.cfg.ServerAPIKey != "") {
		errs = append(errs,
			a.registerGetEventTool(ctx),
			a.registerSearchEventsTool(ctx),
		)
	}

	if a.cfg.PublicMode || (!a.cfg.PublicMode && a.cfg.ManagementAPIKey != "") {
		errs = append(errs,
			a.registerListEnvironmentsTool(ctx),
			a.registerListAPIKeysTool(ctx),
			a.registerGetAPIKeyTool(ctx),
		)

		if !a.cfg.ReadOnly {
			errs = append(errs,
				a.registerCreateEnvironmentTool(ctx),
				a.registerUpdateEnvironmentTool(ctx),
				a.registerDeleteEnvironmentTool(ctx),
				a.registerCreateAPIKeyTool(ctx),
				a.registerUpdateAPIKeyTool(ctx),
				a.registerDeleteAPIKeyTool(ctx),
			)
		}
	}

	return errors.Join(errs...)
}

func (a *App) registerResources(ctx context.Context) error {
	errs := []error{
		a.registerEventSchemaResource(ctx),
		a.registerEnvironmentSchemaResource(ctx),
		a.registerAPIKeySchemaResource(ctx),
	}

	if a.cfg.PublicMode || (!a.cfg.PublicMode && a.cfg.ServerAPIKey != "") {
		errs = append(errs,
			a.registerEventResource(ctx),
		)
	}

	return errors.Join(errs...)
}

func (a *App) run(ctx context.Context) error {
	var err error
	switch a.cfg.Transport {
	case "streamable-http":
		err = a.runStreamableHTTPServer(ctx)
	case "stdio":
		err = a.runStdioServer(ctx)
	default:
		err = fmt.Errorf("unsupported transport: %s. Must be one of: stdio, streamable-http", a.cfg.Transport)
	}

	return err
}
