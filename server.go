package fpmcpserver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/fingerprintjs/fingerprint-mcp-server/config"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
)

type App struct {
	server  *mcp.Server
	cfg     *config.Config
	opts    *opts
	jwks    jwk.Set
	version string
}

type opts struct {
	l       *slog.Logger
	version string
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

func WithVersion(v string) OptFunc {
	return func(o *opts) {
		o.version = v
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

	opts.logger().Info("starting fingerprint-mcp-server", "version", app.version)

	if config.JwksURL != "" {
		if err := app.initJWKS(ctx); err != nil {
			return fmt.Errorf("initializing JWKS: %w", err)
		}
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
	v := opts.version
	if v == "" {
		v = Version()
	}
	a := &App{
		server: mcp.NewServer(
			&mcp.Implementation{
				Name:    "fingerprint-mcp-server",
				Version: v,
			},
			&mcp.ServerOptions{
				//Logger: opts.logger(),
			},
		),
		cfg:     cfg,
		opts:    opts,
		version: v,
	}
	a.server.AddReceivingMiddleware(a.loggingMiddleware)

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

func (a *App) initJWKS(ctx context.Context) error {
	cache := jwk.NewCache(ctx)
	err := cache.Register(a.cfg.JwksURL, jwk.WithMinRefreshInterval(15*time.Minute))
	if err != nil {
		return fmt.Errorf("registering jwks cache: %w", err)
	}

	if _, err := cache.Refresh(ctx, a.cfg.JwksURL); err != nil {
		return fmt.Errorf("fetching JWKS from %s: %w", a.cfg.JwksURL, err)
	}

	a.jwks = jwk.NewCachedSet(cache, a.cfg.JwksURL)
	a.opts.logger().Info("JWKS cache initialized", "url", a.cfg.JwksURL)

	return nil
}

const tokenExtraServerApiKey = "server_api_key"
const tokenExtraMgmtApiKey = "mgmt_api_key"
const tokenExtraRegionKey = "region"

var simpleTokenRe = regexp.MustCompile(`^([a-zA-Z0-9]*)-([a-zA-Z0-9]*)-([a-zA-Z0-9]*)$`)

func (a *App) verifyAuthToken(_ context.Context, authToken string, _ *http.Request) (*auth.TokenInfo, error) {
	var expiration = time.Now().Add(24 * time.Hour) // most tokens never expire

	if a.cfg.AuthToken != "" {
		// Auth token pre-configured, expect it to be passed (likely we're in private mode but in theory could be public too)
		if a.cfg.AuthToken != authToken {
			return nil, auth.ErrInvalidToken
		}

		return &auth.TokenInfo{
			Expiration: expiration,
		}, nil
	} else if a.cfg.PublicMode {
		// Public mode without a pre-configured auth token.
		// API keys are extracted from the bearer token. Two formats are supported:
		// 1) Simple: "serverKey-mgmtKey-region" (dash-separated, alphanumeric, any part can be empty)
		// 2) JWT: a signed JWT whose subject encodes the same three parts
		//
		// We're not doing strict verification here -- just basic sanity checks for user convenience.
		// Actual access verification happens on the backend using the API keys.

		var keys []string

		if matches := simpleTokenRe.FindStringSubmatch(authToken); matches != nil {
			keys = matches[1:4]
		} else if a.oauthEnabled() {
			if a.jwks == nil {
				return nil, fmt.Errorf("JWKS not configured: set JWKS_URL for public mode JWT verification")
			}

			token, err := jwt.Parse([]byte(authToken), jwt.WithKeySet(a.jwks), jwt.WithValidate(true), jwt.WithIssuer(a.cfg.OAuthAuthorizationServer))
			if err != nil {
				a.opts.logger().Error("JWT validation failed", "err", err)
				return nil, auth.ErrInvalidToken
			}

			parts := strings.SplitN(token.Subject(), "-", 3)
			if len(parts) != 3 {
				a.opts.logger().Error("JWT subject must consist of three parts")
				return nil, auth.ErrInvalidToken
			}

			keys = parts
			expiration = token.Expiration()
		}

		allEmpty := true
		for _, value := range keys {
			if len(value) > 0 {
				allEmpty = false
				break
			}
		}
		if allEmpty {
			a.opts.logger().Error("received a token with all parts empty")
			return nil, auth.ErrInvalidToken
		}

		return &auth.TokenInfo{
			Expiration: expiration,
			Extra: map[string]any{
				tokenExtraServerApiKey: keys[0],
				tokenExtraMgmtApiKey:   keys[1],
				tokenExtraRegionKey:    keys[2],
			},
		}, nil
	}

	// we're in private mode, without an auth token pre-configured, so no auth token expected
	return nil, nil
}

func (a *App) oauthEnabled() bool {
	return a.cfg.PublicMode &&
		a.cfg.OAuthAuthorizationServer != "" &&
		a.cfg.OAuthResource != "" &&
		a.cfg.JwksURL != ""
}

func (a *App) handler() http.Handler {
	var mcpHandler http.Handler = mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		return a.server
	}, &mcp.StreamableHTTPOptions{
		Stateless: config.STATELESS,
	})
	mux := http.NewServeMux()

	bearerTokenOptions := &auth.RequireBearerTokenOptions{}

	// only advertise OAuth when we have all we need for it
	if a.oauthEnabled() {
		metadata := &oauthex.ProtectedResourceMetadata{
			Resource: a.cfg.OAuthResource,
			AuthorizationServers: []string{
				a.cfg.OAuthAuthorizationServer,
			},
			BearerMethodsSupported: []string{"header"},
		}
		mux.Handle("/.well-known/oauth-protected-resource", auth.ProtectedResourceMetadataHandler(metadata))

		bearerTokenOptions.ResourceMetadataURL = a.cfg.OAuthResource + "/.well-known/oauth-protected-resource"
	}
	apiKeyAuth := auth.RequireBearerToken(a.verifyAuthToken, bearerTokenOptions)
	mux.Handle("/mcp", apiKeyAuth(mcpHandler))

	// Health check endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	return a.corsMiddleware(mux)
}

func (a *App) runStreamableHTTPServer(_ context.Context) error {
	if a.cfg.AuthToken != "" {
		a.opts.logger().Info("pass auth token in `Authorization: Bearer` http header to access this server", "auth_token", a.cfg.AuthToken)
	}

	handler := a.handler()

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
		err = http.ListenAndServeTLS(addr, a.cfg.TLSCert, a.cfg.TLSKey, handler)
	} else {
		err = http.ListenAndServe(addr, handler)
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
	if a.cfg.AuthToken != "" || a.cfg.PublicMode {
		allowHeaders = append(allowHeaders, "Authorization")
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

func (a *App) loggingMiddleware(next mcp.MethodHandler) mcp.MethodHandler {
	return func(
		ctx context.Context,
		method string,
		req mcp.Request,
	) (mcp.Result, error) {
		var toolName string
		if ctr, ok := req.(*mcp.CallToolRequest); ok {
			toolName = ctr.Params.Name
		}

		a.opts.logger().Debug("MCP method started",
			"method", method,
			"tool_name", toolName,
			"has_params", req.GetParams() != nil,
		)

		start := time.Now()
		result, err := next(ctx, method, req)
		duration := time.Since(start)

		if err != nil {
			a.opts.logger().Error("MCP method failed",
				"method", method,
				"tool_name", toolName,
				"duration_ms", duration.Milliseconds(),
				"err", err,
			)
		} else {
			isError := false
			var ctrError error
			if ctr, ok := result.(*mcp.CallToolResult); ok {
				isError = ctr.IsError
				ctrError = ctr.GetError()
			}

			a.opts.logger().Debug("MCP method completed",
				"method", method,
				"tool_name", toolName,
				"duration_ms", duration.Milliseconds(),
				"has_result", result != nil,
				"is_error", isError,
				"err", ctrError,
			)
		}
		return result, err
	}
}

// readOnlyTools is the set of tools registered when --read-only is used.
var readOnlyTools = []string{
	"get_event",
	"search_events",
	"list_environments",
	"list_api_keys",
	"get_api_key",
}

func (a *App) registerTools(ctx context.Context) error {
	// Resolve the tool filter: explicit --tools takes precedence, then --read-only.
	allowedTools := a.cfg.Tools
	if len(allowedTools) == 0 && a.cfg.ReadOnly {
		allowedTools = readOnlyTools
	}

	shouldRegister := func(name string) bool {
		if len(allowedTools) == 0 {
			return true
		}
		return slices.Contains(allowedTools, name)
	}

	type toolEntry struct {
		name     string
		register func() error
	}

	var candidates []toolEntry

	if a.cfg.PublicMode || (!a.cfg.PublicMode && a.cfg.ServerAPIKey != "") {
		candidates = append(candidates,
			toolEntry{"get_event", func() error { return a.registerGetEventTool(ctx) }},
			toolEntry{"search_events", func() error { return a.registerSearchEventsTool(ctx) }},
		)
	}

	if a.cfg.PublicMode || (!a.cfg.PublicMode && a.cfg.ManagementAPIKey != "") {
		candidates = append(candidates,
			toolEntry{"list_environments", func() error { return a.registerListEnvironmentsTool(ctx) }},
			toolEntry{"list_api_keys", func() error { return a.registerListAPIKeysTool(ctx) }},
			toolEntry{"get_api_key", func() error { return a.registerGetAPIKeyTool(ctx) }},
			toolEntry{"create_environment", func() error { return a.registerCreateEnvironmentTool(ctx) }},
			toolEntry{"update_environment", func() error { return a.registerUpdateEnvironmentTool(ctx) }},
			toolEntry{"delete_environment", func() error { return a.registerDeleteEnvironmentTool(ctx) }},
			toolEntry{"create_api_key", func() error { return a.registerCreateAPIKeyTool(ctx) }},
			toolEntry{"update_api_key", func() error { return a.registerUpdateAPIKeyTool(ctx) }},
			toolEntry{"delete_api_key", func() error { return a.registerDeleteAPIKeyTool(ctx) }},
		)
	}

	var errs []error
	for _, c := range candidates {
		if shouldRegister(c.name) {
			errs = append(errs, c.register())
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
