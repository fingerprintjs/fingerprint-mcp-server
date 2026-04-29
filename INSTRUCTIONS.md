Tools, resources, and prompts for the Fingerprint device intelligence platform (https://fingerprint.com).

## Capabilities

- **Events**: `get_event`, `search_events` return `visitorId`, smart signals (bot, VPN, incognito, …), and request metadata.
- **Management**: `list_/get_/create_/update_/delete_environment` and `_api_key`. Write tools may be disabled — check the tool list.
- **Onboarding**: the `Fingerprint Onboarding Guide` prompt walks through JS Agent install and event verification.
- **Schemas**: event, environment, and API key schemas are exposed as resources.

## Guidance

- Prefer `search_events` over `get_event` unless you have a specific `requestId`.
- `search_events` `start`/`end` are RFC3339 within the last ~90 days; derive from current wall-clock time, not training data.
- Treat the event schema resource as authoritative for field questions.
- API key types: **public** (JS Agent), **secret** (server-to-server), **management** (workspace admin), **proxy** (proxy integrations).
- `delete_environment` / `delete_api_key` are irreversible — confirm first.

## Docs

Prefer v4 over v3 docs unless on a legacy setup. Start at https://docs.fingerprint.com/llms.txt.
