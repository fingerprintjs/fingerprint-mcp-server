package main

const VERSION = "1.0.0"

// config holds the server configuration
type config struct {
	APIKey    string `arg:"required,env:FINGERPRINT_API_KEY" help:"Fingerprint API key"`
	Region    string `arg:"env:FINGERPRINT_REGION" help:"Fingerprint API region. One of: us, eu or asia" default:"us"`
	Transport string `arg:"env:MCP_TRANSPORT" help:"MCP Transport. One of: stdio, streamable-http" default:"stdio"`
	Port      int    `arg:"env:MCP_PORT" help:"MCP Port" default:"8080"`
}

func (c config) Version() string {
	return VERSION
}
