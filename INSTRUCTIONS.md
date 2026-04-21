Fingerprint MCP Server exposes tools, resources, and prompts for working with the Fingerprint device intelligence platform (https://fingerprint.com).

## What you can do with this server

- **Retrieve identification events** with full smart signal data using the `get_event` and `search_events` tools. Events contain a `visitorId` (stable device identifier), smart signals (bot detection, VPN, incognito, etc.), and request metadata.
- **Manage workspace resources** via the management tools: list, create, update, and delete environments and API keys (`list_environments`, `list_api_keys`, `get_api_key`, `create_environment`, `update_environment`, `delete_environment`, `create_api_key`, `update_api_key`, `delete_api_key`). Not all deployments expose the write tools — check the tool list.
- **Onboard Fingerprint into a project** using the `Fingerprint Onboarding Guide` prompt, which walks through installing the JS Agent and verifying that events reach Fingerprint.
- **Inspect schemas** through the exposed resources (event schema, environment schema, API key schema) before calling tools or interpreting results.

## Guidance for using the tools

- Prefer `search_events` over `get_event` when you do not already have a specific `requestId` — it supports filtering by visitor, time range, and smart signals.
- The event schema resource is authoritative. When a user asks about a field, read the schema rather than guessing.
- API keys come in four types: **public** keys are used by the JS Agent in the browser; **secret** (server) keys are used for server-to-server calls; **management** keys used to manager workspace resources; **proxy** keys used for proxy integrations.
- Destructive management operations (`delete_environment`, `delete_api_key`) are irreversible. Confirm with the user before calling them.

## Documentation

Fingerprint has an extensive documentation. Start here when looking for something: https://docs.fingerprint.com/llms.txt