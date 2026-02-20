package config

// VERSION is set at build time via ldflags.
var VERSION = "dev"

const STATELESS = true

// Config holds the server configuration
type Config struct {
	ServerAPIKey     string `arg:"env:FINGERPRINT_SERVER_API_KEY" help:"Fingerprint Server API key (when running in private mode)"`
	ManagementAPIKey string `arg:"env:FINGERPRINT_MANAGEMENT_API_KEY" help:"Fingerprint Management API key (when running in private mode)"`
	Region           string `arg:"env:FINGERPRINT_REGION" help:"Fingerprint API region. One of: us, eu or asia (when running in private mode)" default:"us"`
	Transport        string `arg:"env:MCP_TRANSPORT" help:"MCP Transport. One of: stdio, streamable-http" default:"stdio"`
	Port             int    `arg:"env:MCP_PORT" help:"MCP Port" default:"8080"`
	TLSCert          string `arg:"env:MCP_TLS_CERT" help:"Path to TLS certificate file"`
	TLSKey           string `arg:"env:MCP_TLS_KEY" help:"Path to TLS private key file"`
	ReadOnly         bool   `arg:"env:MCP_READ_ONLY" help:"Skip write tools, only expose read tools"`
	PublicMode       bool   `arg:"env:MCP_PUBLIC" help:"Run in public mode: expect Fingerprint API keys in http headers. If disabled, server will run in private mode using pre-configured API keys."`
	AuthToken        string `arg:"env:MCP_AUTH_TOKEN" help:"Require this token to passed via 'Authorization: Bearer' header to access this server. If not provided and running in private mode, will be generated automatically on startup."`
}

func (c Config) Version() string {
	return VERSION
}
