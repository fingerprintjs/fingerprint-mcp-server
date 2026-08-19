package config

import (
	"github.com/alexflint/go-arg"
)

const STATELESS = true

// Config holds the server configuration
type Config struct {
	ServerAPIKey             string   `arg:"--server-api-key,env:FINGERPRINT_SERVER_API_KEY" help:"Fingerprint Server API key (when running in private mode)"`
	ServerAPIURL             string   `arg:"--server-api-url,env:FINGERPRINT_SERVER_API_URL" help:"Fingerprint Server API url (omit to use default)"`
	ManagementAPIKey         string   `arg:"--management-api-key,env:FINGERPRINT_MANAGEMENT_API_KEY" help:"Fingerprint Management API key (when running in private mode)"`
	ManagementAPIURL         string   `arg:"--management-api-url,env:FINGERPRINT_MANAGEMENT_API_URL" help:"Fingerprint Management API url (omit to use default)"`
	Region                   string   `arg:"env:FINGERPRINT_REGION" help:"Fingerprint API region. One of: us, eu or ap (when running in private mode)" default:"us"`
	Transport                string   `arg:"env:MCP_TRANSPORT" help:"MCP Transport. One of: stdio, streamable-http" default:"stdio"`
	Port                     int      `arg:"env:MCP_PORT" help:"MCP Port" default:"8080"`
	TLSCert                  string   `arg:"--tls-cert,env:MCP_TLS_CERT" help:"Path to TLS certificate file"`
	TLSKey                   string   `arg:"--tls-key,env:MCP_TLS_KEY" help:"Path to TLS private key file"`
	ReadOnly                 bool     `arg:"--read-only,env:MCP_READ_ONLY" help:"Skip write tools, only expose read tools (shorthand for --tools with only read tools)"`
	Tools                    []string `arg:"env:MCP_TOOLS" help:"Comma-separated list of tool names to register (overrides --read-only)"`
	PublicMode               bool     `arg:"--public,env:MCP_PUBLIC" help:"Run in public mode: expect Fingerprint API keys in http headers. If disabled, server will run in private mode using pre-configured API keys."`
	AuthToken                string   `arg:"--auth-token,env:MCP_AUTH_TOKEN" help:"Require this token to passed via 'Authorization: Bearer' header to access this server. If not provided and running in private mode, will be generated automatically on startup."`
	JwtPublicKey             string   `arg:"--jwt-public-key,env:FINGERPRINT_PUBLIC_KEY" help:"PEM-encoded ES256 public key for verifying Fingerprint-issued JWT tokens"`
	OAuthResource            string   `arg:"--oauth-resource,env:OAUTH_RESOURCE" help:"URL of this server"`
	OAuthAuthorizationServer string   `arg:"--oauth-auth-server,env:OAUTH_AUTH_SERVER" help:"URL of the OAuth authorization server"`
	JwksURL                  string   `arg:"--jwks-url,env:JWKS_URL" help:"JWKS URL for JWT token verification in public mode"`
}

func MustParse() *Config {
	cfg := &Config{}
	arg.MustParse(cfg)
	return cfg
}
