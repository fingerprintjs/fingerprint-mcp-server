Tools, resources, and prompts for the Fingerprint device intelligence platform (https://fingerprint.com).

## Capabilities

- **Events**: `get_event`, `search_events` return `visitorId`, smart signals (bot, VPN, incognito, …), and request metadata.
- **Management**: `list_/get_/create_/update_/delete_environment` and `_api_key`. Write tools may be disabled — check the tool list.
- **Onboarding**: the `Fingerprint Onboarding Guide` prompt walks through JS Agent install and event verification.
- **Schemas**: event, environment, and API key schemas are exposed as resources.
- **Discovery**: `list_tools` reports the read-only tools this server is serving right now, and `call_tool` runs any of them.

## Guidance

- Prefer `search_events` over `get_event` unless you have a specific `requestId`.
- `search_events` `start`/`end` are RFC3339; derive from current wall-clock time, not training data.
- Event timestamps (`timestamp`, `first_seen_at`, `last_seen_at`) come back as RFC3339 UTC strings, read them as-is, no conversion.
- `factory_reset_timestamp` is the exception: Unix epoch milliseconds, where `0` means no factory reset was detected.
- If a Fingerprint tool you expect is not in your available tools, call `list_tools` before concluding it does not exist. Your list can be out of date, and anything `list_tools` returns can be run with `call_tool`.
- Treat the event schema resource as authoritative for field questions.
- API key types: **public** (JS Agent), **secret** (server-to-server), **management** (workspace admin), **proxy** (proxy integrations).
- `delete_environment` / `delete_api_key` are irreversible — confirm first.

## Docs

Prefer v4 over v3 docs unless on a legacy setup. Start at https://docs.fingerprint.com/llms.txt.
