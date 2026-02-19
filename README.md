# Fingerprint MCP Server

An MCP (Model Context Protocol) server for [Fingerprint](https://fingerprint.com/) - a device intelligence platform for web security and anti-fraud.

## Features

- **Event tools**: Retrieve and search identification events with full smart signal data
- **Management tools**: Manage workspace environments and API keys
- **Onboarding prompt**: Guided setup for integrating Fingerprint into a project
- Supports both **stdio** and **streamable-http** transports
- Optional HTTPS with TLS certificates
- **Public mode** for multi-tenant deployments (API keys passed via HTTP headers)
- **Read-only mode** to expose only read tools
- Configurable via environment variables or CLI flags
- Docker support for easy deployment

## Installation

### From Source

```bash
go install github.com/fingerprintjs/fingerprint-mcp-server@latest
```

### Build Locally

```bash
git clone https://github.com/fingerprintjs/fingerprint-mcp-server.git
cd fingerprint-mcp-server
go generate ./...
go build -o fingerprint-mcp-server .
```

`go generate` downloads the OpenAPI spec and generates schema files under `internal/schema/`. These are gitignored and must be regenerated before building.

## Configuration

The server can be configured via CLI flags or environment variables:

| CLI Flag | Environment Variable | Default | Description |
|----------|---------------------|---------|-------------|
| `--server-api-key` | `FINGERPRINT_SERVER_API_KEY` | (required in private mode) | Fingerprint Server API key |
| `--management-api-key` | `FINGERPRINT_MANAGEMENT_API_KEY` | | Fingerprint Management API key (enables management tools) |
| `--region` | `FINGERPRINT_REGION` | `us` | API region: `us`, `eu`, or `asia` |
| `--transport` | `MCP_TRANSPORT` | `stdio` | Transport: `stdio` or `streamable-http` |
| `--port` | `MCP_PORT` | `8080` | Port for HTTP/HTTPS server |
| `--tls-cert` | `MCP_TLS_CERT` | | Path to TLS certificate file |
| `--tls-key` | `MCP_TLS_KEY` | | Path to TLS private key file |
| `--read-only` | `MCP_READ_ONLY` | `false` | Only expose read tools (no create/update/delete) |
| `--public` | `MCP_PUBLIC` | `false` | Public mode: expect API keys in HTTP headers instead of config |
| `--auth-token` | `MCP_AUTH_TOKEN` | (auto-generated) | Bearer token required to access the server |

## Usage

### Stdio Transport (Default)

```bash
export FINGERPRINT_SERVER_API_KEY=your-secret-api-key
./fingerprint-mcp-server
```

### Streamable HTTP Transport

```bash
export FINGERPRINT_SERVER_API_KEY=your-secret-api-key
./fingerprint-mcp-server --transport=streamable-http --port=8080
```

The MCP endpoint will be available at `http://localhost:8080/mcp`.

### HTTPS

Provide TLS certificate and key files to enable HTTPS:

```bash
./fingerprint-mcp-server --transport=streamable-http \
  --tls-cert=cert.pem --tls-key=key.pem
```

## Docker

### Build the Image

```bash
docker build -t fingerprint-mcp-server .
```

### Run with Stdio Transport

```bash
docker run -i --rm \
  -e FINGERPRINT_SERVER_API_KEY=your-secret-api-key \
  fingerprint-mcp-server
```

### Run with Streamable HTTP Transport

```bash
docker run -d --rm \
  -e FINGERPRINT_SERVER_API_KEY=your-secret-api-key \
  -e MCP_TRANSPORT=streamable-http \
  -p 8080:8080 \
  fingerprint-mcp-server
```

## MCP Client Configuration

### Claude Desktop

Add to your Claude Desktop configuration file (`claude_desktop_config.json`):

**Stdio Transport:**
```json
{
  "mcpServers": {
    "fingerprint": {
      "command": "/path/to/fingerprint-mcp-server",
      "env": {
        "FINGERPRINT_SERVER_API_KEY": "your-secret-api-key"
      }
    }
  }
}
```

**Docker with Stdio:**
```json
{
  "mcpServers": {
    "fingerprint": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "-e", "FINGERPRINT_SERVER_API_KEY=your-secret-api-key", "fingerprint-mcp-server"]
    }
  }
}
```

## Available Tools

### Event Tools

These tools require a Server API key.

#### get_event

Retrieves detailed information about a specific identification event.

**Input:**
- `event_id` (string, required): The unique identifier of the identification event
- `products` (string[], optional): Product fields to include in the response

#### search_events

Searches for events matching various filters with pagination.

**Input:**
- `limit` (integer, required): Number of events to return
- `visitor_id`, `ip_address`, `linked_id` — identity filters
- `bot`, `vpn`, `proxy`, `incognito`, `tampering`, and other smart signal filters
- `start`, `end` — time range in Unix milliseconds
- `pagination_key` — for paginating through results
- `products` (string[], optional): Product fields to include in the response

Both tools return comprehensive event data including visitor identification, browser details, geolocation, bot detection, and smart signals.

### Management Tools

These tools require a Management API key. Write tools are hidden when `--read-only` is set.

#### list_environments

Lists all workspace environments with pagination support.

#### list_api_keys

Lists API keys with optional filters by type (`public`/`secret`/`proxy`), status (`enabled`/`disabled`), and environment.

#### get_api_key

Retrieves detailed information about a specific API key by its ID.

#### create_environment

Creates a new workspace environment with name, description, and optional rate limits.

#### update_environment

Updates an existing workspace environment.

#### delete_environment

Deletes a workspace environment (only if it has no active API keys).

#### create_api_key

Creates a new API key of a given type (`public`/`secret`/`proxy`).

#### update_api_key

Updates an existing API key (name, description, status, rate limit).

#### delete_api_key

Deletes an API key. This operation is irreversible.

## Available Resources

- **`fingerprint://events/{event_id}`** — Returns full event data for a given event ID.
- **`fingerprint://schemas/event`** — JSON Schema describing the event output structure.
- **`fingerprint://schemas/environment`** — JSON Schema for environment objects.
- **`fingerprint://schemas/api-key`** — JSON Schema for API key objects.

## Available Prompts

- **`onboarding`** — A guided walkthrough for integrating Fingerprint into a project, covering JavaScript Agent installation, API key setup, and verification steps.

## Regional API Endpoints

Fingerprint provides regional API endpoints for data locality requirements:

- **US (default)**: `api.fpjs.io`
- **EU**: `eu.api.fpjs.io`
- **Asia Pacific**: `ap.api.fpjs.io`

Use the `--region` flag or `FINGERPRINT_REGION` environment variable to select your region.

## License

MIT
