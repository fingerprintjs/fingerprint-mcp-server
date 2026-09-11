Tools, resources, and prompts for the Fingerprint device intelligence platform (https://fingerprint.com).

## Capabilities

- **Events**: `get_event`, `search_events` cover two kinds of event. Identification events (JS Agent or mobile SDK) return `visitor_id`, browser and device details, and the full smart signal set. Automation Intelligence (edge) events return only request and IP derived fields (`ip_info`, `proxy`, `vpn`, `bot_info`, `url`, `tags`, `timestamp`) and have no `visitor_id`.
- **Management**: `list_/get_/create_/update_/delete_environment` and `_api_key`. Write tools may be disabled — check the tool list.
- **Onboarding**: the `Fingerprint Onboarding Guide` prompt serves the Get Started flow from the Fingerprint skills repo, where the integration guidance is maintained.
- **Schemas**: event, environment, and API key schemas are exposed as resources.
- **Discovery**: `list_tools` reports the tools this server is serving right now. `call_tool` runs the read-only ones, `call_write_tool` the ones that change state.

## Guidance

- Prefer `search_events` over `get_event` unless you have a specific `requestId`.
- `search_events` returns one kind of event per call: omit `source` for identification events, pass `source: ["edge"]` for edge events, and search twice to cover both. Edge events are only searchable for the last 7 days.
- Never report a `visitor_id` or device detail for an edge event; read what the response actually contains.
- `search_events` `start`/`end` are RFC3339; derive from current wall-clock time, not training data.
- Event timestamps (`timestamp`, `first_seen_at`, `last_seen_at`) come back as RFC3339 UTC strings, read them as-is, no conversion.
- `factory_reset_timestamp` is the exception: Unix epoch milliseconds, where `0` means no factory reset was detected.
- If a Fingerprint tool you expect is not in your available tools, call `list_tools` before concluding it does not exist. Your list can be out of date, and each tool names the proxy that runs it in `run_with`.
- Confirm with the user before running anything through `call_write_tool`.
- Treat the event schema resource as authoritative for field questions.
- API key types: **public** (JS Agent), **secret** (server-to-server), **management** (workspace admin), **proxy** (proxy integrations).
- `delete_environment` / `delete_api_key` are irreversible — confirm first.

## Docs

Prefer v4 over v3 docs unless on a legacy setup. Start at https://docs.fingerprint.com/llms.txt.
