# Fingerprint MCP Server

An MCP (Model Context Protocol) server for [Fingerprint](https://fingerprint.com/) - a device intelligence platform for web security and anti-fraud.

## Features

- **get_event** tool: Retrieves detailed information about a specific identification event by its event ID.
- **search_events** tool: Searches for events matching various criteria (visitor ID, IP address, bot detection, smart signals, etc.) with pagination support.
- Supports both **stdio** and **SSE** transport protocols
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

`go generate` downloads the OpenAPI spec and generates `schema_generated.go` and supporting JSON files. These are gitignored and must be regenerated before building.

## Configuration

The server can be configured via CLI flags or environment variables:

| CLI Flag | Environment Variable | Default | Description |
|----------|---------------------|---------|-------------|
| `--api-key` | `FINGERPRINT_API_KEY` | (required) | Your Fingerprint secret API key |
| `--region` | `FINGERPRINT_REGION` | `us` | API region: `us`, `eu`, or `ap` |
| `--transport` | `MCP_TRANSPORT` | `stdio` | Transport protocol: `stdio` or `sse` |
| `--port` | `MCP_PORT` | `8080` | Port for SSE server |

## Usage

### Stdio Transport (Default)

```bash
# Using environment variable
export FINGERPRINT_API_KEY=your-secret-api-key
./fingerprint-mcp-server

# Using CLI flag
./fingerprint-mcp-server --api-key=your-secret-api-key
```

### SSE Transport

```bash
export FINGERPRINT_API_KEY=your-secret-api-key
./fingerprint-mcp-server --transport=sse --port=8080
```

The SSE endpoint will be available at `http://localhost:8080/sse`.

## Docker

### Build the Image

```bash
docker build -t fingerprint-mcp-server .
```

### Run with Stdio Transport

```bash
docker run -i --rm \
  -e FINGERPRINT_API_KEY=your-secret-api-key \
  fingerprint-mcp-server
```

### Run with SSE Transport

```bash
docker run -d --rm \
  -e FINGERPRINT_API_KEY=your-secret-api-key \
  -e MCP_TRANSPORT=sse \
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
        "FINGERPRINT_API_KEY": "your-secret-api-key"
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
      "args": ["run", "-i", "--rm", "-e", "FINGERPRINT_API_KEY=your-secret-api-key", "fingerprint-mcp-server"]
    }
  }
}
```

## Available Tools

### get_event

Retrieves detailed information about a specific identification event.

**Input:**
- `event_id` (string, required): The unique identifier of the identification event
- `products` (string[], optional): Product fields to include in the response

### search_events

Searches for events matching various filters with pagination.

**Input:**
- `limit` (integer, required): Number of events to return
- `visitor_id`, `ip_address`, `linked_id` — identity filters
- `bot`, `vpn`, `proxy`, `incognito`, `tampering`, and other smart signal filters
- `start`, `end` — time range in Unix milliseconds
- `pagination_key` — for paginating through results
- `products` (string[], optional): Product fields to include in the response

Both tools return comprehensive event data including visitor identification, browser details, geolocation, bot detection, and smart signals.

## Available Resources

- **`fingerprint://events/{event_id}`** — Returns full event data for a given event ID.
- **`fingerprint://schemas/event`** — JSON Schema describing the event output structure.

## Regional API Endpoints

Fingerprint provides regional API endpoints for data locality requirements:

- **US (default)**: `api.fpjs.io`
- **EU**: `eu.api.fpjs.io`
- **Asia Pacific**: `ap.api.fpjs.io`

Use the `--region` flag or `FINGERPRINT_REGION` environment variable to select your region.

## License

MIT
