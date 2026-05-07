package fpmcpserver

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/fingerprintjs/fingerprint-mcp-server/config"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
)

//go:embed INSTRUCTIONS.md
var instructions string

type App struct {
	server       *mcp.Server
	cfg          *config.Config
	opts         *opts
	jwks         jwk.Set
	jwtPublicKey jwk.Key
	version      string
	appName      string
}

type opts struct {
	l       *slog.Logger
	version string
	appName string
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

func WithAppName(appName string) OptFunc {
	return func(o *opts) {
		o.appName = appName
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
	appName := opts.appName
	if appName == "" {
		appName = "fingerprint-mcp-server"
	}
	a := &App{
		server: mcp.NewServer(
			&mcp.Implementation{
				Name:    appName,
				Version: v,
			},
			&mcp.ServerOptions{
				//Logger: opts.logger(),
				Instructions: instructions,
			},
		),
		cfg:     cfg,
		opts:    opts,
		version: v,
		appName: appName,
	}
	a.server.AddReceivingMiddleware(a.loggingMiddleware)

	if cfg.JwtPublicKey != "" {
		if err := a.initJwtPublicKey(); err != nil {
			return nil, err
		}
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

const fpjsJWTIssuer = "https://api.fpjs.pro"

func (a *App) initJwtPublicKey() error {
	key, err := jwk.ParseKey([]byte(a.cfg.JwtPublicKey), jwk.WithPEM(true))
	if err != nil {
		return fmt.Errorf("parsing JWT public key PEM: %w", err)
	}
	a.jwtPublicKey = key
	a.opts.logger().Info("JWT public key initialized")
	return nil
}

// verifyJWT parses and verifies a JWT token. It peeks at the issuer claim
// to determine which key to use for signature verification:
//   - fpjsJWTIssuer → verify with the configured ES256 public key
//   - OAuthAuthorizationServer → verify with the JWKS keyset
func (a *App) verifyJWT(rawToken string) (jwt.Token, error) {
	// Parse without verification to peek at the issuer.
	unverified, err := jwt.Parse([]byte(rawToken), jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		return nil, fmt.Errorf("parsing JWT: %w", err)
	}

	issuer := unverified.Issuer()

	switch {
	case issuer == fpjsJWTIssuer && a.jwtPublicKey != nil:
		return jwt.Parse([]byte(rawToken),
			jwt.WithKey(jwa.ES256, a.jwtPublicKey),
			jwt.WithValidate(true),
			jwt.WithIssuer(fpjsJWTIssuer),
		)
	case issuer == a.cfg.OAuthAuthorizationServer && a.oauthEnabled() && a.jwks != nil:
		return jwt.Parse([]byte(rawToken),
			jwt.WithKeySet(a.jwks),
			jwt.WithValidate(true),
			jwt.WithIssuer(a.cfg.OAuthAuthorizationServer),
		)
	default:
		return nil, fmt.Errorf("no key configured for JWT issuer %q", issuer)
	}
}

const tokenExtraServerApiKey = "server_api_key"
const tokenExtraMgmtApiKey = "mgmt_api_key"
const tokenExtraRegionKey = "region"
const tokenExtraSubscriptionID = "subscription_id"

const claimSubscriptionID = "urn:fingerprint:sub_id"

// parseKeysDashSeparated splits s into exactly 3 dash-separated parts
// representing serverAPIKey, managementAPIKey, and region.
// Returns an error if s doesn't contain exactly 3 parts or all parts are empty.
func parseKeysDashSeparated(s string) ([]string, error) {
	parts := strings.SplitN(s, "-", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("expected 3 dash-separated parts, got %d", len(parts))
	}
	if parts[0] == "" && parts[1] == "" && parts[2] == "" {
		return nil, fmt.Errorf("all parts are empty")
	}
	return parts, nil
}

func (a *App) verifyAuthToken(_ context.Context, authToken string, _ *http.Request) (*auth.TokenInfo, error) {
	if a.cfg.AuthToken != "" {
		// Auth token pre-configured, expect it to be passed (likely we're in private mode but in theory could be public too)
		if a.cfg.AuthToken != authToken {
			return nil, auth.ErrInvalidToken
		}

		return &auth.TokenInfo{
			Expiration: time.Now().Add(24 * time.Hour),
		}, nil
	} else if a.cfg.PublicMode {
		// Public mode without a pre-configured auth token.
		// API keys are extracted from a JWT whose subject encodes three dash-separated parts:
		// serverAPIKey-managementAPIKey-region
		//
		// Actual access verification happens on the backend using the API keys.

		token, err := a.verifyJWT(authToken)
		if err != nil {
			a.opts.logger().Error("JWT validation failed", "err", err)
			return nil, auth.ErrInvalidToken
		}

		keys, err := parseKeysDashSeparated(token.Subject())
		if err != nil {
			a.opts.logger().Error("JWT subject is invalid", "err", err)
			return nil, auth.ErrInvalidToken
		}

		extra := map[string]any{
			tokenExtraServerApiKey: keys[0],
			tokenExtraMgmtApiKey:   keys[1],
			tokenExtraRegionKey:    keys[2],
		}
		if subID, ok := token.Get(claimSubscriptionID); ok {
			extra[tokenExtraSubscriptionID] = subID
		}

		return &auth.TokenInfo{
			Expiration: token.Expiration(),
			Extra:      extra,
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
	// All authentication data is passed via Authorization headers, so we can disable cross origin protection
	crossOriginProtection := http.NewCrossOriginProtection()
	crossOriginProtection.AddInsecureBypassPattern("/")

	var mcpHandler http.Handler = mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		return a.server
	}, &mcp.StreamableHTTPOptions{
		Stateless:             config.STATELESS,
		CrossOriginProtection: crossOriginProtection,
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
		var toolName, resourceURI, promptName, clientInfo string
		if ctr, ok := req.(*mcp.CallToolRequest); ok {
			toolName = ctr.Params.Name
		}
		// resource_uri is logged as-is. Today the only templated URI is
		// fingerprint://events/{event_id}, where event_id is an opaque
		// server-issued identifier; the rest are static fingerprint://schemas/*
		// URIs. Re-evaluate redaction here if a future resource embeds
		// customer-identifying data directly in the URI.
		if rr, ok := req.(*mcp.ReadResourceRequest); ok {
			resourceURI = rr.Params.URI
		}
		if pr, ok := req.(*mcp.GetPromptRequest); ok {
			promptName = pr.Params.Name
		}
		if ir, ok := req.(*mcp.ServerRequest[*mcp.InitializeParams]); ok {
			if ci := ir.Params.ClientInfo; ci != nil {
				clientInfo = ci.Name + "/" + ci.Version
			}
		}
		subID, _ := req.GetExtra().TokenInfo.Extra[tokenExtraSubscriptionID].(string) // subID is optional

		// baseAttrs returns the common attributes for every log line. Optional
		// fields are only included when populated to avoid empty-string noise on
		// methods that don't carry them (e.g. resource_uri on tools/call).
		baseAttrs := func() []any {
			attrs := []any{"method", method}
			if toolName != "" {
				attrs = append(attrs, "tool_name", toolName)
			}
			if resourceURI != "" {
				attrs = append(attrs, "resource_uri", resourceURI)
			}
			if promptName != "" {
				attrs = append(attrs, "prompt_name", promptName)
			}
			if subID != "" {
				attrs = append(attrs, "sub_id", subID)
			}
			if clientInfo != "" {
				attrs = append(attrs, "client_info", clientInfo)
			}
			return attrs
		}

		a.opts.logger().Debug("MCP method started", append(baseAttrs(), "has_params", req.GetParams() != nil)...)

		start := time.Now()
		result, err := next(ctx, method, req)
		duration := time.Since(start)

		if err != nil {
			a.opts.logger().Error("MCP method failed", append(baseAttrs(),
				"duration_ms", duration.Milliseconds(),
				"err", err,
			)...)
			return result, err
		}

		isError := false
		var ctrError error
		if ctr, ok := result.(*mcp.CallToolResult); ok {
			isError = ctr.IsError
			ctrError = ctr.GetError()
		}
		a.opts.logger().Debug("MCP method completed", append(baseAttrs(),
			"duration_ms", duration.Milliseconds(),
			"has_result", result != nil,
			"is_error", isError,
			"err", ctrError,
		)...)
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
