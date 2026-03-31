<p align="center">
    <a href="https://fingerprint.com">
        <picture>
            <source media="(prefers-color-scheme: dark)" srcset="https://fingerprintjs.github.io/home/resources/logo_light.svg" />
            <source media="(prefers-color-scheme: light)" srcset="https://fingerprintjs.github.io/home/resources/logo_dark.svg" />
            <img src="https://fingerprintjs.github.io/home/resources/logo_dark.svg" alt="Fingerprint logo" width="312px" />
        </picture>
    </a>
</p>

# Fingerprint MCP Server

## Features

- **Event tools**: Retrieve and search identification events with full smart signal data
- **Management tools**: Manage workspace environments and API keys
- **Onboarding prompt**: Guided setup for integrating Fingerprint into a project
- Supports both **stdio** and **streamable-http** transports
- Optional HTTPS with TLS certificates
- OAuth2 login supported
- **Public mode** for multi-tenant deployments (API keys passed via JWT bearer token)
- **Tool filtering** to control which tools are exposed
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
make build
```

`make build` runs `go generate` (to download the OpenAPI spec and generate schema files under `internal/schema/`) and then builds the binary.

## Configuration

The server can be configured via CLI flags or environment variables:

| CLI Flag               | Environment Variable             | Default                          | Description                                                              |
|------------------------|----------------------------------|----------------------------------|--------------------------------------------------------------------------|
| `--server-api-key`     | `FINGERPRINT_SERVER_API_KEY`     |                                  | Fingerprint Server API key (private mode)                                |
| `--server-api-url`     | `FINGERPRINT_SERVER_API_URL`     | api.fpjs.io                      | Custom Server API URL (omit to use default)                              |
| `--management-api-key` | `FINGERPRINT_MANAGEMENT_API_KEY` |                                  | Fingerprint Management API key (private mode)                            |
| `--management-api-url` | `FINGERPRINT_MANAGEMENT_API_URL` | management-api.fpjs.io           | Custom Management API URL (omit to use default)                          |
| `--region`             | `FINGERPRINT_REGION`             | `us`                             | API region: `us`, `eu`, or `ap` (private mode)                           |
| `--transport`          | `MCP_TRANSPORT`                  | `stdio`                          | Transport: `stdio` or `streamable-http`                                  |
| `--port`               | `MCP_PORT`                       | `8080`                           | Port for HTTP/HTTPS server                                               |
| `--tls-cert`           | `MCP_TLS_CERT`                   |                                  | Path to TLS certificate file                                             |
| `--tls-key`            | `MCP_TLS_KEY`                    |                                  | Path to TLS private key file                                             |
| `--read-only`          | `MCP_READ_ONLY`                  | `false`                          | Only expose read tools (shorthand for `--tools` with read-only tools)    |
| `--tools`              | `MCP_TOOLS`                      |                                  | Comma-separated list of tool names to register (overrides `--read-only`) |
| `--public`             | `MCP_PUBLIC`                     | `false`                          | Public mode: extract API keys from JWT bearer tokens                     |
| `--auth-token`         | `MCP_AUTH_TOKEN`                 | (auto-generated in private mode) | Bearer token required to access the server (private mode)                |
| `--jwt-public-key`     | `FINGERPRINT_PUBLIC_KEY`         |                                  | PEM-encoded ES256 public key for verifying Fingerprint-issued JWT tokens |
| `--oauth-resource`     | `OAUTH_RESOURCE`                 |                                  | URL of this server (for OAuth metadata)                                  |
| `--oauth-auth-server`  | `OAUTH_AUTH_SERVER`              |                                  | URL of the OAuth authorization server                                    |
| `--jwks-url`           | `JWKS_URL`                       |                                  | JWKS URL for JWT token verification in public mode                       |

## Usage

### Private mode vs. Public mode

Private mode means the server runs with its API keys pre-configured (FINGERPRINT_SERVER_API_KEY and FINGERPRINT_MANAGEMENT_API_KEY). This mode is useful when you are running a local instance intended to be used within your organization: server automatically uses those specified in the config. In this mode, auth token (MCP_AUTH_TOKEN) is enforced to protect your instance of the MCP server from unauthenticated use.

Public mode is how https://mcp.fpjs.io/mcp is run. It is meant to be used in situations when a single instance can be used by different users from different organizations, each with their own API keys. In this mode, API keys are extracted from JWT access tokens that are issued by https://dashboard.fingerprint.com or by user following the OAuth2 flow.

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

### Tool Filtering

By default, all tools are registered based on which API keys are configured. You can restrict which tools are exposed:

```bash
# Only expose read-only tools
./fingerprint-mcp-server --read-only

# Expose a specific set of tools
./fingerprint-mcp-server --tools=get_event,search_events,list_environments
```

When `--tools` is set, it overrides `--read-only`.

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

Add to your Cursor/Claude Desktop/etc configuration file (e.g. `claude_desktop_config.json`):

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

**Streamable HTTP Transport:**
```json
{
  "mcpServers": {
    "fingerprint": {
      "url": "https://url/mcp",
      "headers": {
        "Authorization": "Bearer <auth-token>"
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

Event tools require a Server API key. Management tools require a Management API key. Write tools (create/update/delete) are hidden when `--read-only` is set or excluded via `--tools`.

| Tool                 | Description                                                         |
|----------------------|---------------------------------------------------------------------|
| `get_event`          | Retrieve a specific identification event by ID                      |
| `search_events`      | Search events with filters (visitor, IP, smart signals, time range) |
| `list_environments`  | List workspace environments with pagination                         |
| `get_api_key`        | Get details of a specific API key                                   |
| `list_api_keys`      | List API keys with optional type/status/environment filters         |
| `create_environment` | Create a new workspace environment                                  |
| `update_environment` | Update an existing workspace environment                            |
| `delete_environment` | Delete a workspace environment                                      |
| `create_api_key`     | Create a new API key (public/secret/proxy)                          |
| `update_api_key`     | Update an existing API key                                          |
| `delete_api_key`     | Delete an API key (irreversible)                                    |

## Available Resources

- **`fingerprint://events/{event_id}`** — Returns full event data for a given event ID.
- **`fingerprint://schemas/event`** — JSON Schema describing the event output structure.
- **`fingerprint://schemas/environment`** — JSON Schema for environment objects.
- **`fingerprint://schemas/api-key`** — JSON Schema for API key objects.

## Available Prompts

- **`onboarding`** — A guided walkthrough for integrating Fingerprint into a project, covering JavaScript Agent installation, API key setup, and verification steps.

## License

MIT
